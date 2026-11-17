#!/usr/bin/env python3
"""nsec3check.py - DNSSEC の「その名前は存在しない」という証明（NSEC / NSEC3）を読む

使い方:
    ./nsec3check.py example.jp [example.org ...]      ゾーンを指定して実測（DoH: dns.google）
    ./nsec3check.py --fixture fixtures/live-2026-11-18.txt   保存済みの応答を読む（オフライン）
    ./nsec3check.py --hash www.example.jp - 0          NSEC3 ハッシュだけ計算（名前 ソルト 反復回数）

ゾーン頂点の NSEC3PARAM と、存在しない名前への応答（Authority セクション）を取り、
  - 不在証明の方式（NSEC / NSEC3 / RFC 9824 の Compact Denial / 署名なし）
  - NSEC3 のパラメータが RFC 9276 の推奨（1 0 0 -）に合っているか
  - 応答に入っている NSEC / NSEC3 が、本当にその名前の不在を証明しているか
を表示します。RRSIG の署名検証はしません（リゾルバの AD ビットを表示するだけ）。
Python 標準ライブラリだけで動きます。
"""
import base64
import hashlib
import json
import sys
import time
import urllib.request

TIMEOUT = 10
UA = 'nsec3check/1.0'
T_A, T_SOA, T_NSEC, T_NSEC3, T_NSEC3PARAM = 1, 6, 47, 50, 51

_B32 = bytes.maketrans(b'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',
                       b'0123456789ABCDEFGHIJKLMNOPQRSTUV')
_B32R = bytes.maketrans(b'0123456789ABCDEFGHIJKLMNOPQRSTUV',
                        b'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567')


# ---------------------------------------------------------------- 名前の扱い

def labels(name):
    """提示形式の名前をラベル（bytes）のリストにする。小文字化する。

    \\DDD（10進3桁）と \\X のエスケープを解く。'.' や '' はルート（空リスト）。
    """
    out, cur, i = [], bytearray(), 0
    s = name
    while i < len(s):
        c = s[i]
        if c == '\\':
            if s[i + 1:i + 4].isdigit() and len(s[i + 1:i + 4]) == 3:
                v = int(s[i + 1:i + 4])
                if v > 255:
                    raise ValueError('\\DDD が 255 を超えている: %r' % name)
                cur.append(v)
                i += 4
            else:
                if i + 1 >= len(s):
                    raise ValueError('末尾が \\ で終わっている: %r' % name)
                cur.append(ord(s[i + 1]))
                i += 2
        elif c == '.':
            if not cur and i != len(s) - 1 and len(s) > 1:
                raise ValueError('空ラベル: %r' % name)
            if cur:
                out.append(bytes(cur).lower())
            cur = bytearray()
            i += 1
        else:
            cur += c.encode('utf-8')
            i += 1
    if cur:
        out.append(bytes(cur).lower())
    for l in out:
        if len(l) > 63:
            raise ValueError('ラベルが 63 オクテットを超えている: %r' % name)
    return out


def to_wire(lbls):
    """ラベル列をワイヤ形式にする（圧縮なし・小文字。RFC 4034 6.2 の正規形）"""
    return b''.join(bytes([len(l)]) + l for l in lbls) + b'\x00'


def to_text(lbls):
    if not lbls:
        return '.'
    out = []
    for l in lbls:
        out.append(''.join(chr(b) if 0x21 <= b <= 0x7e and b not in (0x2e, 0x5c)
                           else '\\%03d' % b for b in l))
    return '.'.join(out) + '.'


def canon_key(lbls):
    """RFC 4034 6.1 の正規順序の比較キー。

    いちばん右のラベルから順に、各ラベルを符号なしオクテット列として比べる。
    「オクテットが無い」は 0 より前。Python の tuple と bytes の比較がそのまま合う。
    """
    return tuple(reversed(lbls))


def in_span(owner, nxt, x):
    """owner < x < nxt か。連鎖の最後の 1 本（nxt <= owner）は末尾から先頭へ回り込む。"""
    if owner < nxt:
        return owner < x < nxt
    return x > owner or x < nxt


# ---------------------------------------------------------------- NSEC3 ハッシュ

def b32hex(b):
    return base64.b32encode(b).translate(_B32).decode().rstrip('=').lower()


def b32hex_decode(s):
    s = s.upper()
    s += '=' * (-len(s) % 8)
    return base64.b32decode(s.encode().translate(_B32R))


def salt_bytes(salt):
    return b'' if salt in ('-', '') else bytes.fromhex(salt)


def nsec3_hash(name, salt='-', iterations=0, alg=1):
    """RFC 5155 5 節。IH(salt, x, 0) = H(x || salt)、IH(salt, x, k) = H(IH(salt, x, k-1) || salt)

    iterations は「追加で」回す回数。0 でも SHA-1 は 1 回かかる。
    """
    if alg != 1:
        raise ValueError('NSEC3 ハッシュアルゴリズム %d は未定義（1 = SHA-1 のみ）' % alg)
    lbls = name if isinstance(name, list) else labels(name)
    s = salt_bytes(salt)
    d = hashlib.sha1(to_wire(lbls) + s).digest()
    for _ in range(iterations):
        d = hashlib.sha1(d + s).digest()
    return d


# ---------------------------------------------------------------- レコードの解釈

def type_name(t):
    return 'NXNAME' if t.upper() == 'TYPE128' else t.upper()


def parse_nsec3(owner, rdata):
    f = rdata.split()
    if len(f) < 5:
        raise ValueError('NSEC3 の RDATA が短い: %r' % rdata)
    ol = labels(owner)
    if not ol:
        raise ValueError('NSEC3 の所有者名がルート')
    return {
        'owner_hash': b32hex_decode(ol[0].decode()),
        'zone': ol[1:],
        'alg': int(f[0]), 'flags': int(f[1]), 'iterations': int(f[2]),
        'salt': f[3].lower(),
        'next_hash': b32hex_decode(f[4]),
        'types': [type_name(t) for t in f[5:]],
        'optout': bool(int(f[1]) & 1),
    }


def parse_nsec(owner, rdata):
    f = rdata.split()
    return {'owner': labels(owner), 'next': labels(f[0]),
            'types': [type_name(t) for t in f[1:]]}


def parse_fixture_line(line):
    p = [x.strip() for x in line.split(' | ')]
    if len(p) != 6:
        raise ValueError('フィクスチャの列数が 6 でない: %r' % line[:60])

    def recs(s, tag):
        if not s.startswith(tag):
            raise ValueError('%s で始まっていない: %r' % (tag, s[:20]))
        s = s[len(tag):].strip()
        out = []
        for r in s.split(' || '):
            r = r.strip()
            if not r:
                continue
            f = r.split(None, 2)
            out.append((int(f[0]), f[1], f[2] if len(f) > 2 else ''))
        return out
    return {'qname': p[0], 'qtype': int(p[1]),
            'status': int(p[2]) if p[2].isdigit() else p[2],
            'ad': p[3] == '1',
            'answer': recs(p[4], 'AN:'), 'authority': recs(p[5], 'AU:')}


def load_fixture(path):
    out = []
    for line in open(path, encoding='utf-8'):
        line = line.rstrip('\n')
        if line.strip() and not line.startswith('#'):
            out.append(parse_fixture_line(line))
    return out


def doh(name, rtype):
    url = 'https://dns.google/resolve?name=%s&type=%d&do=1' % (name, rtype)
    req = urllib.request.Request(url, headers={'User-Agent': UA})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        j = json.load(r)

    def recs(key):
        return [(a['type'], a['name'], a.get('data', '')) for a in j.get(key, [])
                if a.get('type') != 46]
    return {'qname': name, 'qtype': rtype, 'status': j.get('Status'),
            'ad': bool(j.get('AD')), 'answer': recs('Answer'), 'authority': recs('Authority')}


# ---------------------------------------------------------------- パラメータの評価

def assess_params(alg, flags, iterations, salt, optout=None):
    """RFC 9276 3.1 に照らす。戻り値は (レベル, メッセージ) のリスト。"""
    notes = []
    if alg != 1:
        notes.append(('WARN', 'ハッシュアルゴリズム %d は未定義' % alg))
    if iterations != 0:
        notes.append(('WARN', '追加の反復回数が %d（RFC 9276 3.1: 0 にしなければならない MUST。'
                      '検証側は 0 より大きい応答を insecure 扱いや SERVFAIL にしてよい）' % iterations))
    if salt not in ('-', ''):
        notes.append(('NOTE', 'ソルトあり（%d オクテット。RFC 9276 3.1: 使うべきでない SHOULD NOT）'
                      % len(salt_bytes(salt))))
    if optout:
        notes.append(('NOTE', 'Opt-Out あり（RFC 9276 3.1: 小さなゾーンでは NOT RECOMMENDED。'
                      '委任の大半が未署名の巨大なゾーンでは MAY）'))
    if not notes:
        notes.append(('OK', 'RFC 9276 の推奨どおり（SHA-1・追加反復 0・ソルトなし'
                      + ('・Opt-Out なし' if optout is False else '') + '）'))
    return notes


# ---------------------------------------------------------------- 不在証明の検証

def nsec3_proof(qname, nsec3s):
    """RFC 5155 8.3 の closest encloser proof と、8.4 のワイルドカード不在。

    戻り値: dict（ok, closest_encloser, next_closer, cover_nc, cover_wc, problems）
    """
    res = {'ok': False, 'problems': [], 'closest_encloser': None, 'next_closer': None,
           'cover_nc': None, 'cover_wc': None, 'match_ce': None}
    zone = nsec3s[0]['zone']
    params = set((n['alg'], n['iterations'], n['salt']) for n in nsec3s)
    if len(params) != 1 or any(n['zone'] != zone for n in nsec3s):
        res['problems'].append('応答内の NSEC3 のパラメータかゾーンが揃っていない')
        return res
    alg, iters, salt = params.pop()
    q = labels(qname)
    if len(q) < len(zone) or (zone and q[-len(zone):] != zone):
        res['problems'].append('問い合わせ名が NSEC3 のゾーン %s の配下でない' % to_text(zone))
        return res

    def h(lbls):
        return nsec3_hash(lbls, salt, iters, alg)

    def match(lbls):
        x = h(lbls)
        for n in nsec3s:
            if n['owner_hash'] == x:
                return n
        return None

    def cover(lbls):
        x = h(lbls)
        for n in nsec3s:
            if in_span(n['owner_hash'], n['next_hash'], x):
                return n
        return None

    # 8.3: SNAME を QNAME から 1 ラベルずつ削る
    sname, flag, prev = q, False, None
    while len(sname) >= len(zone):
        m = match(sname)
        if m is None:
            flag = cover(sname) is not None
            prev = sname
        else:
            if flag:
                res['closest_encloser'], res['match_ce'] = sname, m
                res['next_closer'], res['cover_nc'] = prev, cover(prev)
            else:
                res['problems'].append('%s に一致する NSEC3 はあるが、1 ラベル長い名前を覆う NSEC3 が無い'
                                       '（8.3: bogus）' % to_text(sname))
            break
        if not sname:
            break
        sname = sname[1:]
    if res['closest_encloser'] is None:
        if not res['problems']:
            res['problems'].append('closest encloser に一致する NSEC3 が応答に無い')
        return res
    ce_types = res['match_ce']['types']
    if 'DNAME' in ce_types or ('NS' in ce_types and 'SOA' not in ce_types):
        res['problems'].append('closest encloser の NSEC3 が委任点か DNAME（8.3: このゾーンの証明に使えない）')
    wc = [b'*'] + res['closest_encloser']
    res['cover_wc'] = cover(wc)
    if res['cover_wc'] is None:
        res['problems'].append('ワイルドカード %s を覆う NSEC3 が無い（8.4）' % to_text(wc))
    res['hashes'] = {to_text(res['closest_encloser']): b32hex(h(res['closest_encloser'])),
                     to_text(res['next_closer']): b32hex(h(res['next_closer'])),
                     to_text(wc): b32hex(h(wc))}
    res['ok'] = not res['problems']
    return res


def common_suffix(a, b):
    n = 0
    while n < len(a) and n < len(b) and a[-1 - n] == b[-1 - n]:
        n += 1
    return a[len(a) - n:]


def nsec_proof(qname, nsecs):
    """RFC 4035 5.4: QNAME を覆う NSEC と、closest encloser のワイルドカードを覆う NSEC。"""
    res = {'ok': False, 'problems': [], 'cover_q': None, 'cover_wc': None, 'closest_encloser': None}
    q = labels(qname)
    qk = canon_key(q)
    for n in nsecs:
        if in_span(canon_key(n['owner']), canon_key(n['next']), qk):
            res['cover_q'] = n
            break
    if res['cover_q'] is None:
        res['problems'].append('問い合わせ名を覆う NSEC が無い')
        return res
    n = res['cover_q']
    ce = max(common_suffix(q, n['owner']), common_suffix(q, n['next']), key=len)
    res['closest_encloser'] = ce
    wc = [b'*'] + ce
    wk = canon_key(wc)
    for m in nsecs:
        if in_span(canon_key(m['owner']), canon_key(m['next']), wk):
            res['cover_wc'] = m
            break
    if res['cover_wc'] is None:
        res['problems'].append('ワイルドカード %s を覆う NSEC が無い' % to_text(wc))
    res['ok'] = not res['problems']
    return res


def classify(resp):
    """存在しない名前への応答を読む。戻り値は dict（kind と詳細）。"""
    q = labels(resp['qname'])
    nsec3s = [parse_nsec3(o, d) for t, o, d in resp['authority'] if t == T_NSEC3]
    nsecs = [parse_nsec(o, d) for t, o, d in resp['authority'] if t == T_NSEC]
    out = {'status': resp['status'], 'ad': resp['ad'], 'kind': None}
    if resp['answer']:
        out['kind'] = 'answer'      # ワイルドカード展開など。名前は「存在する」ことにされた
        return out
    if nsec3s:
        # QNAME そのものに一致する NSEC3 があれば、これは「名前はある・型が無い」の応答（8.5）。
        # RFC 9824 の NSEC3 版 Compact Denial もこの形で返る（型ビットマップが NXNAME だけ）
        for n in nsec3s:
            if n['owner_hash'] == nsec3_hash(q, n['salt'], n['iterations'], n['alg']):
                out['nsec3_match'] = n
                out['minimal'] = (int.from_bytes(n['owner_hash'], 'big') + 1) % (1 << 160) == \
                    int.from_bytes(n['next_hash'], 'big')
                out['kind'] = ('compact-nxname' if 'NXNAME' in n['types']
                               else 'compact-plain' if not n['types'] else 'nodata')
                return out
        out['kind'] = 'nsec3'
        out['nsec3'] = nsec3s
        out['proof'] = nsec3_proof(resp['qname'], nsec3s)
        cn = out['proof'].get('cover_nc')
        # 9.2: next closer を覆う NSEC3 が Opt-Out なら AD を立ててはならない
        out['ad_allowed'] = not (cn and cn['optout'])
        return out
    if nsecs:
        exact = [n for n in nsecs if n['owner'] == q]
        if exact:
            n = exact[0]
            out['nsec'] = n
            out['minimal'] = n['next'] == [b'\x00'] + q
            out['kind'] = 'compact-nxname' if 'NXNAME' in n['types'] else 'compact-plain'
            return out
        out['kind'] = 'nsec'
        out['nsecs'] = nsecs
        out['proof'] = nsec_proof(resp['qname'], nsecs)
        return out
    out['kind'] = 'unsigned'
    return out


# ---------------------------------------------------------------- 表示

RCODE = {0: 'NOERROR', 2: 'SERVFAIL', 3: 'NXDOMAIN'}
KIND = {'nsec3': 'NSEC3', 'nsec': 'NSEC', 'compact-nxname': 'Compact Denial（NXNAME あり・RFC 9824）',
        'compact-plain': 'QNAME と同名の NSEC / NSEC3（NXNAME なし）',
        'nodata': 'QNAME に一致する NSEC3（名前はある・その型が無い）',
        'answer': '応答あり（名前は存在する扱い）', 'unsigned': '不在証明なし（未署名、または証明が返っていない）'}


def report(param_resp, nx_resp, out=None):
    w = (out or sys.stdout).write
    zone = param_resp['qname']
    w('=' * 60 + '\n%s\n' % zone + '=' * 60 + '\n')
    pr = [d for t, o, d in param_resp['answer'] if t == T_NSEC3PARAM]
    c = classify(nx_resp)
    if pr:
        f = pr[0].split()
        w('  NSEC3PARAM : %s\n' % pr[0])
    else:
        w('  NSEC3PARAM : なし\n')
    w('  問い合わせ : %s A\n' % nx_resp['qname'])
    w('  応答       : %s / AD=%d\n' % (RCODE.get(c['status'], c['status']), c['ad']))
    w('  不在証明   : %s\n' % KIND[c['kind']])
    if c['kind'] == 'nsec3':
        n0 = c['nsec3'][0]
        optout = any(n['optout'] for n in c['nsec3'])
        for lv, msg in assess_params(n0['alg'], n0['flags'], n0['iterations'], n0['salt'], optout):
            w('    [%s] %s\n' % (lv, msg))
        p = c['proof']
        if p['ok']:
            w('    closest encloser : %s\n' % to_text(p['closest_encloser']))
            for nm, hv in p['hashes'].items():
                w('      H(%s) = %s\n' % (nm, hv))
            w('    next closer を覆う NSEC3 : %s → %s%s\n' % (
                b32hex(p['cover_nc']['owner_hash']), b32hex(p['cover_nc']['next_hash']),
                '（Opt-Out）' if p['cover_nc']['optout'] else ''))
            w('    ワイルドカードを覆う NSEC3 : %s → %s\n' % (
                b32hex(p['cover_wc']['owner_hash']), b32hex(p['cover_wc']['next_hash'])))
            w('    [OK] 3 本の NSEC3 で不在が成り立つ（署名は未検証）\n')
            if not c['ad_allowed']:
                w('    [NOTE] next closer を覆う NSEC3 が Opt-Out。RFC 5155 9.2 により AD は立たない'
                  '（観測: AD=%d）\n' % c['ad'])
        else:
            for m in p['problems']:
                w('    [NG] %s\n' % m)
    elif c['kind'] == 'nsec':
        p = c['proof']
        if p['ok']:
            w('    QNAME を覆う NSEC : %s → %s\n' % (to_text(p['cover_q']['owner']), to_text(p['cover_q']['next'])))
            w('    closest encloser : %s\n' % to_text(p['closest_encloser']))
            w('    ワイルドカードを覆う NSEC : %s → %s\n' % (to_text(p['cover_wc']['owner']), to_text(p['cover_wc']['next'])))
            w('    [OK] 不在が成り立つ（署名は未検証）\n')
            w('    [NOTE] NSEC は実在する名前をそのまま載せる。たどればゾーンの中身が列挙できる\n')
        else:
            for m in p['problems']:
                w('    [NG] %s\n' % m)
    elif c['kind'].startswith('compact') or c['kind'] == 'nodata':
        if 'nsec' in c:
            n = c['nsec']
            w('    NSEC : %s → %s  %s\n' % (to_text(n['owner']), to_text(n['next']), ' '.join(n['types'])))
        else:
            n = c['nsec3_match']
            w('    NSEC3 : %s → %s  %s\n' % (b32hex(n['owner_hash']), b32hex(n['next_hash']),
                                             ' '.join(n['types']) or '（型なし）'))
        if c['kind'] == 'nodata':
            pass
        elif c['kind'] == 'compact-nxname':
            w('    [OK] 型ビットマップに NXNAME（TYPE128）。RFC 9824: 名前は存在しない、の合図\n')
        else:
            w('    [NOTE] NXNAME が無い。この応答だけでは「存在しない名前」と'
              '「レコードを持たない実在の名前（ENT）」を区別できない（RFC 9824 2 節）\n')
        if c['status'] == 0:
            w('    [NOTE] RCODE は NOERROR。NXDOMAIN を数える監視やスクリプトはこの応答を数えない\n')
    elif c['kind'] == 'answer':
        w('    [NOTE] 存在しないはずの名前に Answer が返った（ワイルドカード等）。不在証明は対象外\n')
    return c


def summarize(pairs, out=None):
    w = (out or sys.stdout).write
    rows = [(p['qname'], [d for t, o, d in p['answer'] if t == T_NSEC3PARAM], classify(n)) for p, n in pairs]
    w('\n集計（%d ゾーン）\n' % len(rows))
    kinds = {}
    for z, pr, c in rows:
        kinds.setdefault(c['kind'], []).append(z)
    for k in ('nsec3', 'nsec', 'compact-nxname', 'compact-plain', 'answer', 'unsigned'):
        if k in kinds:
            w('  %-10s %2d  %s\n' % (k, len(kinds[k]), ' '.join(kinds[k])))
    n3 = [(z, c) for z, pr, c in rows if c['kind'] == 'nsec3']
    it = [z for z, c in n3 if c['nsec3'][0]['iterations'] != 0]
    sa = [z for z, c in n3 if c['nsec3'][0]['salt'] != '-']
    oo = [z for z, c in n3 if any(n['optout'] for n in c['nsec3'])]
    best = [z for z, c in n3 if c['nsec3'][0]['iterations'] == 0 and c['nsec3'][0]['salt'] == '-']
    w('  NSEC3 のうち 追加反復 > 0 : %d  %s\n' % (len(it), ' '.join(it)))
    w('  NSEC3 のうち ソルトあり   : %d  %s\n' % (len(sa), ' '.join(sa)))
    w('  NSEC3 のうち Opt-Out      : %d  %s\n' % (len(oo), ' '.join(oo)))
    w('  NSEC3 のうち 反復 0・ソルトなし : %d  %s\n' % (len(best), ' '.join(best)))
    bad = [z for z, c in n3 if not c['proof']['ok']] + \
          [z for z, pr, c in rows if c['kind'] == 'nsec' and not c['proof']['ok']]
    w('  不在証明が成り立たなかった : %d  %s\n' % (len(bad), ' '.join(bad)))
    mism = [z for z, c in n3 if c['ad'] and not c['ad_allowed']]
    w('  Opt-Out なのに AD=1 : %d  %s\n' % (len(mism), ' '.join(mism)))
    return rows


def pairs_from(resps):
    pairs, i = [], 0
    while i + 1 < len(resps):
        if resps[i]['qtype'] == T_NSEC3PARAM and resps[i + 1]['qtype'] == T_A:
            pairs.append((resps[i], resps[i + 1]))
            i += 2
        else:
            i += 1
    return pairs


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 0
    if argv[1] == '--hash':
        if len(argv) != 5:
            print('使い方: --hash 名前 ソルト(16進か -) 反復回数')
            return 2
        print(b32hex(nsec3_hash(argv[2], argv[3], int(argv[4]))))
        return 0
    if argv[1] == '--fixture':
        pairs = pairs_from(load_fixture(argv[2]))
        for p, n in pairs:
            report(p, n)
        summarize(pairs)
        return 0
    label = 'zz-nsec3check-%d' % int(time.time())
    for z in argv[1:]:
        z = z.rstrip('.')
        apex = (z + '.') if z else '.'
        nx = label + '.' + z + '.' if z else label + '.'
        try:
            report(doh(apex, T_NSEC3PARAM), doh(nx, T_A))
        except Exception as e:
            print('%s: 取得失敗 %s: %s' % (apex, type(e).__name__, e))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
