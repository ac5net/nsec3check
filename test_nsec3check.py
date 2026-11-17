#!/usr/bin/env python3
"""nsec3check.py のテスト。ネットワークに出ません。

    python3 test_nsec3check.py

RFC 5155 Appendix A / B のハッシュ値と応答例、RFC 9824 4 節の例、RFC 4034 6.1 の並び順の例を
そのまま期待値にしています。fixtures/ は 2026-11-18 に dns.google から取得した応答です。
"""
import hashlib
import io
import os

import nsec3check as m

HERE = os.path.dirname(os.path.abspath(__file__))
fails, count = [], 0


def check(name, got, want):
    global count
    count += 1
    if got == want:
        print('ok   %s' % name)
    else:
        print('FAIL %s\n       got  %r\n       want %r' % (name, got, want))
        fails.append(name)


def raises(name, fn):
    global count
    count += 1
    try:
        fn()
    except ValueError:
        print('ok   %s' % name)
    else:
        print('FAIL %s（ValueError にならない）' % name)
        fails.append(name)


# --- RFC 5155 Appendix A: ハッシュのテストベクタ（NSEC3PARAM 1 0 12 aabbccdd） ---------------
APP_A = [
    ('example', '0p9mhaveqvm6t7vbl5lop2u3t2rp3tom'),
    ('a.example', '35mthgpgcu1qg68fab165klnsnk3dpvl'),
    ('ai.example', 'gjeqe526plbf1g8mklp59enfd789njgi'),
    ('ns1.example', '2t7b4g4vsa5smi47k61mv5bv1a22bojr'),
    ('ns2.example', 'q04jkcevqvmu85r014c7dkba38o0ji5r'),
    ('w.example', 'k8udemvp1j2f7eg6jebps17vp3n8i58h'),
    ('*.w.example', 'r53bq7cc2uvmubfu5ocmm6pers9tk9en'),
    ('x.w.example', 'b4um86eghhds6nea196smvmlo4ors995'),
    ('y.w.example', 'ji6neoaepv8b5o6k4ev33abha8ht9fgc'),
    ('x.y.w.example', '2vptu5timamqttgl4luu9kg21e0aor3s'),
    ('xx.example', 't644ebqk9bibcna874givr6joj62mlhv'),
    ('2t7b4g4vsa5smi47k61mv5bv1a22bojr.example', 'kohar7mbb8dc2ce8a9qvl8hon4k53uhi'),
    # Appendix B の応答例に出てくる値
    ('c.x.w.example', '0va5bpr2ou0vk0lbqeeljri88laipsfh'),
    ('*.x.w.example', '92pqneegtaue7pjatc3l3qnk738c6v5m'),
    ('c.example', '4g6p9u5gvfshp30pqecj98b3maqbn1ck'),
    ('z.w.example', 'qlu7gtfaeh0ek0c05ksfhdpbcgglbe03'),
]
for name, want in APP_A:
    check('RFC 5155 App.A/B: H(%s)' % name, m.b32hex(m.nsec3_hash(name, 'aabbccdd', 12)), want)

# 末尾ドットの有無、大文字小文字、ソルトの大文字で結果が変わらないこと（5 節: 正規形は小文字・完全修飾）
check('末尾ドットあり', m.b32hex(m.nsec3_hash('example.', 'aabbccdd', 12)), APP_A[0][1])
check('大文字の名前', m.b32hex(m.nsec3_hash('X.W.Example', 'AABBCCDD', 12)), APP_A[7][1])

# 「追加の」反復回数: 0 でも SHA-1 は 1 回かかる（RFC 5155 3.1.3 / RFC 9276 2.3）
wire = b'\x07example\x00'
check('iterations=0 は SHA-1 を 1 回', m.nsec3_hash('example', '-', 0), hashlib.sha1(wire).digest())
check('iterations=1 は SHA-1 を 2 回', m.nsec3_hash('example', '-', 1),
      hashlib.sha1(hashlib.sha1(wire).digest()).digest())
check('ソルトは毎回の入力の後ろに付く', m.nsec3_hash('example', 'aabbccdd', 1),
      hashlib.sha1(hashlib.sha1(wire + bytes.fromhex('aabbccdd')).digest() + bytes.fromhex('aabbccdd')).digest())
raises('ハッシュアルゴリズム 2 は未定義', lambda: m.nsec3_hash('example', '-', 0, alg=2))

# --- RFC 9824 4 節: NSEC3 での Compact Denial の例（1 0 0 -） -------------------------------
h = m.nsec3_hash('a.example.com', '-', 0)
check('RFC 9824 4: H(a.example.com)', m.b32hex(h), 'h64kfa4p1acer2ebps9qsdk6dnp8b3jq')
succ = (int.from_bytes(h, 'big') + 1).to_bytes(20, 'big')
check('RFC 9824 4: 次のハッシュ = ハッシュ + 1', m.b32hex(succ), 'h64kfa4p1acer2ebps9qsdk6dnp8b3jr')

# --- base32hex ----------------------------------------------------------------------------
check('base32hex の往復', m.b32hex(m.b32hex_decode('0P9MHAVEQVM6T7VBL5LOP2U3T2RP3TOM')), APP_A[0][1])
check('base32hex は大文字小文字を区別しない', m.b32hex_decode('ck0pojmg874ljref7efn8430qvit8bsm'),
      m.b32hex_decode('CK0POJMG874LJREF7EFN8430QVIT8BSM'))
check('通常の base32 と取り違えていない（全ゼロは 0 の並び）', m.b32hex(b'\x00' * 20), '0' * 32)

# --- 名前の解釈 ---------------------------------------------------------------------------
check('ルート', m.labels('.'), [])
check('空文字もルート', m.labels(''), [])
check('小文字化', m.labels('WWW.Example.JP.'), [b'www', b'example', b'jp'])
check('\\000 ラベル', m.labels('\\000.a.example.com.'), [b'\x00', b'a', b'example', b'com'])
check('\\. はラベル内のドット', m.labels('a\\.b.example.'), [b'a.b', b'example'])
check('ワイヤ形式', m.to_wire(m.labels('a.example')), b'\x01a\x07example\x00')
check('ルートのワイヤ形式', m.to_wire([]), b'\x00')
check('提示形式に戻す（\\000）', m.to_text([b'\x00', b'a']), '\\000.a.')
check('提示形式に戻す（ルート）', m.to_text([]), '.')
raises('\\DDD が 255 超', lambda: m.labels('\\256.example.'))
raises('64 オクテットのラベル', lambda: m.labels('a' * 64 + '.example.'))
raises('空ラベル', lambda: m.labels('a..example.'))

# --- RFC 4034 6.1: 正規順序の例 -----------------------------------------------------------
ORDER = ['example', 'a.example', 'yljkjljk.a.example', 'Z.a.example', 'zABC.a.EXAMPLE',
         'z.example', '\\001.z.example', '*.z.example', '\\200.z.example']
shuffled = [ORDER[i] for i in (4, 8, 0, 6, 2, 7, 1, 5, 3)]
check('RFC 4034 6.1 の例の並び', sorted(shuffled, key=lambda n: m.canon_key(m.labels(n))), ORDER)
check('単純な文字列ソートでは合わない', sorted(shuffled) == ORDER, False)

# --- 区間の判定 ---------------------------------------------------------------------------
check('区間の内側', m.in_span(b'\x10', b'\x20', b'\x15'), True)
check('所有者名そのものは「覆う」ではない（一致）', m.in_span(b'\x10', b'\x20', b'\x10'), False)
check('次の名前そのものも覆わない', m.in_span(b'\x10', b'\x20', b'\x20'), False)
check('連鎖の最後: 末尾側', m.in_span(b'\xf0', b'\x05', b'\xf8'), True)
check('連鎖の最後: 先頭側', m.in_span(b'\xf0', b'\x05', b'\x01'), True)
check('連鎖の最後: 範囲外', m.in_span(b'\xf0', b'\x05', b'\x80'), False)
check('1 本だけの連鎖（自分に戻る）は自分以外を全部覆う', m.in_span(b'\x10', b'\x10', b'\x99'), True)

# --- RFC 5155 B.1: Name Error の応答例 ----------------------------------------------------
B1 = [
    ('0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example.',
     '1 1 12 aabbccdd 2t7b4g4vsa5smi47k61mv5bv1a22bojr MX DNSKEY NS SOA NSEC3PARAM RRSIG'),
    ('b4um86eghhds6nea196smvmlo4ors995.example.',
     '1 1 12 aabbccdd gjeqe526plbf1g8mklp59enfd789njgi MX RRSIG'),
    ('35mthgpgcu1qg68fab165klnsnk3dpvl.example.',
     '1 1 12 aabbccdd b4um86eghhds6nea196smvmlo4ors995 NS DS RRSIG'),
]


def resp(qname, recs, status=3, ad=False, rtype=50):
    return {'qname': qname, 'qtype': 1, 'status': status, 'ad': ad, 'answer': [],
            'authority': [(rtype, o, d) for o, d in recs]}


c = m.classify(resp('a.c.x.w.example.', B1))
p = c['proof']
check('B.1: 方式', c['kind'], 'nsec3')
check('B.1: 証明が成り立つ', p['ok'], True)
check('B.1: closest encloser', m.to_text(p['closest_encloser']), 'x.w.example.')
check('B.1: next closer', m.to_text(p['next_closer']), 'c.x.w.example.')
check('B.1: next closer を覆う NSEC3', m.b32hex(p['cover_nc']['owner_hash']), '0p9mhaveqvm6t7vbl5lop2u3t2rp3tom')
check('B.1: ワイルドカードを覆う NSEC3', m.b32hex(p['cover_wc']['owner_hash']), '35mthgpgcu1qg68fab165klnsnk3dpvl')
check('B.1: next closer 側が Opt-Out なので AD 不可（9.2）', c['ad_allowed'], False)
check('B.1: 大文字の問い合わせ名でも同じ', m.classify(resp('A.C.X.W.EXAMPLE.', B1))['proof']['ok'], True)
check('B.1: 所有者ハッシュが大文字でも同じ',
      m.classify(resp('a.c.x.w.example.', [(o.upper(), d) for o, d in B1]))['proof']['ok'], True)

c = m.classify(resp('a.c.x.w.example.', B1[:2]))
check('B.1 からワイルドカード側を抜くと不成立', c['proof']['ok'], False)
check('その理由は 8.4', '8.4' in c['proof']['problems'][0], True)
c = m.classify(resp('a.c.x.w.example.', [B1[0], B1[2]]))
check('B.1 から closest encloser の一致を抜くと不成立', c['proof']['ok'], False)
c = m.classify(resp('a.c.x.w.example.', [B1[1], B1[2]]))
check('B.1 から next closer の覆いを抜くと不成立', c['proof']['ok'], False)
check('その理由は 8.3 の bogus', 'bogus' in c['proof']['problems'][0], True)
c = m.classify(resp('a.c.x.w.example.net.', B1))
check('別ゾーンの名前には使えない', c['proof']['ok'], False)
mixed = [B1[0], B1[1], (B1[2][0], B1[2][1].replace(' 12 ', ' 11 '))]
check('反復回数が混ざった応答は不成立', m.classify(resp('a.c.x.w.example.', mixed))['proof']['ok'], False)
# closest encloser が委任点（NS あり・SOA なし）の NSEC3 は使えない
deleg = [B1[0], (B1[1][0], B1[1][1].replace('MX RRSIG', 'NS DS RRSIG')), B1[2]]
check('closest encloser が委任点なら不成立', m.classify(resp('a.c.x.w.example.', deleg))['proof']['ok'], False)

# Opt-Out でない NSEC3 なら AD 可
noopt = [(o, d.replace('1 1 12', '1 0 12')) for o, d in B1]
check('Opt-Out なしなら AD 可', m.classify(resp('a.c.x.w.example.', noopt))['ad_allowed'], True)

# --- RFC 9824: Compact Denial ------------------------------------------------------------
c = m.classify(resp('a.example.com.', [('a.example.com.', '\\000.a.example.com. RRSIG NSEC NXNAME')],
                    status=0, ad=True, rtype=47))
check('RFC 9824 3.1 の例（NXNAME）', c['kind'], 'compact-nxname')
check('次の名前は \\000 を前置した直後の名前', c['minimal'], True)
c = m.classify(resp('a.example.com.', [('a.example.com.', '\\000.a.example.com. RRSIG NSEC TYPE128')],
                    status=0, ad=True, rtype=47))
check('TYPE128 と書かれていても NXNAME', c['kind'], 'compact-nxname')
c = m.classify(resp('a.example.com.', [('a.example.com.', '\\000.a.example.com. RRSIG NSEC')],
                    status=0, ad=True, rtype=47))
check('NXNAME なしは ENT と区別できない', c['kind'], 'compact-plain')
c = m.classify(resp('a.example.com.',
                    [('H64KFA4P1ACER2EBPS9QSDK6DNP8B3JQ.example.com.', '1 0 0 - H64KFA4P1ACER2EBPS9QSDK6DNP8B3JR NXNAME')],
                    status=0, ad=True))
check('RFC 9824 4 の例（NSEC3 + NXNAME）', c['kind'], 'compact-nxname')
c = m.classify(resp('a.example.com.',
                    [('H64KFA4P1ACER2EBPS9QSDK6DNP8B3JQ.example.com.', '1 0 0 - H64KFA4P1ACER2EBPS9QSDK6DNP8B3JR')],
                    status=0, ad=True))
check('NSEC3 で型ビットマップが空なら ENT（NXNAME なし）', c['kind'], 'compact-plain')
check('NSEC3 の次のハッシュが +1（最小の区間）', c['minimal'], True)
c = m.classify(resp('ns1.example.', [('2t7b4g4vsa5smi47k61mv5bv1a22bojr.example.',
                                      '1 1 12 aabbccdd 2vptu5timamqttgl4luu9kg21e0aor3s A RRSIG')], status=0))
check('RFC 5155 B.2 の例（No Data: 名前はあり MX が無い）', c['kind'], 'nodata')
c = m.classify(resp('y.w.example.', [('ji6neoaepv8b5o6k4ev33abha8ht9fgc.example.',
                                      '1 1 12 aabbccdd k8udemvp1j2f7eg6jebps17vp3n8i58h')], status=0))
check('RFC 5155 B.2.1 の例（ENT: 型ビットマップが空）', c['kind'], 'compact-plain')
buf0 = io.StringIO()
m.report({'qname': 'example.', 'answer': []}, resp('y.w.example.', [('ji6neoaepv8b5o6k4ev33abha8ht9fgc.example.',
         '1 1 12 aabbccdd k8udemvp1j2f7eg6jebps17vp3n8i58h')], status=0), buf0)
check('NSEC3 の ENT 応答も表示できる', '（型なし）' in buf0.getvalue(), True)

# --- NSEC の証明 --------------------------------------------------------------------------
ROOT = [('.', 'aaa. NS SOA RRSIG NSEC DNSKEY TYPE63'), ('zw.', '. NS RRSIG NSEC')]
c = m.classify(resp('zz-ac5net-nx-20261118.', ROOT, ad=True, rtype=47))
check('ルート: 方式', c['kind'], 'nsec')
check('ルート: 成立', c['proof']['ok'], True)
check('ルート: closest encloser はルート', c['proof']['closest_encloser'], [])
check('ルート: QNAME を覆うのは連鎖の最後の 1 本', m.to_text(c['proof']['cover_q']['owner']), 'zw.')
c = m.classify(resp('zz-ac5net-nx-20261118.', ROOT[:1], ad=True, rtype=47))
check('ルート: 最後の 1 本を抜くと不成立', c['proof']['ok'], False)
SE = [('se.', '0.se. NS SOA TXT RRSIG NSEC'), ('zz.se.', 'zz-naltradlulea.se. NS RRSIG NSEC')]
check('se: 接頭辞が同じラベルの間に入る', m.classify(resp('zz-ac5net-nx-20261118.se.', SE, rtype=47))['proof']['ok'], True)
check('se: 範囲の外の名前は覆われない', m.classify(resp('zzz.se.', SE, rtype=47))['proof']['ok'], False)

# --- パラメータの評価（RFC 9276 3.1） ------------------------------------------------------
lv = lambda *a: [x[0] for x in m.assess_params(*a)]
check('1 0 0 - は OK', lv(1, 0, 0, '-', False), ['OK'])
check('反復 1 は WARN', lv(1, 0, 1, '-', False), ['WARN'])
check('ソルトは NOTE', lv(1, 0, 0, 'aabb', False), ['NOTE'])
check('Opt-Out は NOTE', lv(1, 0, 0, '-', True), ['NOTE'])
check('全部入り', lv(1, 0, 10, 'aef123ab', True), ['WARN', 'NOTE', 'NOTE'])

# --- 実測データ（2026-11-18） --------------------------------------------------------------
pairs = m.pairs_from(m.load_fixture(os.path.join(HERE, 'fixtures', 'live-2026-11-18.txt')))
check('ゾーン数', len(pairs), 37)
buf = io.StringIO()
rows = m.summarize(pairs, buf)
kinds = {}
for z, pr, c in rows:
    kinds.setdefault(c['kind'], []).append(z)
check('NSEC3 のゾーン数', len(kinds['nsec3']), 27)
check('NSEC のゾーン', kinds['nsec'], ['.', 'se.', 'ch.', 'br.', 'defo.ie.'])
check('NXNAME 付き Compact Denial', kinds['compact-nxname'], ['cloudflare.com.', 'ietf.org.'])
check('NXNAME なしの同名 NSEC', kinds['compact-plain'], ['soumu.go.jp.'])
check('ワイルドカードで応答が返る', kinds['answer'], ['slack.com.'])
check('未署名', kinds['unsigned'], ['ac-5.net.'])
n3 = [(z, c) for z, pr, c in rows if c['kind'] == 'nsec3']
check('NSEC3 の証明は全部成立', [z for z, c in n3 if not c['proof']['ok']], [])
check('NSEC の証明は全部成立', [z for z, pr, c in rows if c['kind'] == 'nsec' and not c['proof']['ok']], [])
check('追加反復 > 0', [z for z, c in n3 if c['nsec3'][0]['iterations']], ['dev.', 'app.', 'google.', 'cn.'])
check('cn の反復回数', dict(n3)['cn.']['nsec3'][0]['iterations'], 10)
check('ソルトあり', len([z for z, c in n3 if c['nsec3'][0]['salt'] != '-']), 10)
tld = [(z, c) for z, c in n3 if z.count('.') == 1]
check('TLD の NSEC3 は 21', len(tld), 21)
check('TLD で 1 0 0 - は 14', len([z for z, c in tld if c['nsec3'][0]['iterations'] == 0 and c['nsec3'][0]['salt'] == '-']), 14)
oo = [z for z, c in n3 if any(n['optout'] for n in c['nsec3'])]
check('Opt-Out は 16（全部 TLD）', (len(oo), all(z.count('.') == 1 for z in oo)), (16, True))
check('Opt-Out の応答はすべて AD=0', [z for z, c in n3 if z in oo and c['ad']], [])
check('Opt-Out でない NSEC3 の応答はすべて AD=1', [z for z, c in n3 if z not in oo and not c['ad']], [])
check('ad_allowed と観測した AD が全ゾーンで一致', [z for z, c in n3 if c['ad_allowed'] != c['ad']], [])
check('NSEC3PARAM の値と NSEC3 の値が一致',
      [z for z, pr, c in rows if c['kind'] == 'nsec3' and
       (int(pr[0].split()[2]), pr[0].split()[3]) != (c['nsec3'][0]['iterations'], c['nsec3'][0]['salt'])], [])
check('NSEC3PARAM のフラグは全部 0', [z for z, pr, c in rows if pr and pr[0].split()[1] != '0'], [])
check('cn: next closer を覆うのは連鎖の最後の 1 本（回り込み）',
      dict(n3)['cn.']['proof']['cover_nc']['next_hash'] < dict(n3)['cn.']['proof']['cover_nc']['owner_hash'], True)
check('NOERROR で返った「存在しない名前」', [z for z, pr, c in rows if c['status'] == 0],
      ['cloudflare.com.', 'slack.com.', 'ietf.org.', 'soumu.go.jp.'])

# 実測値を 1 文字壊すと不成立になること（テストが何でも通す作りになっていないことの確認）
p, n = pairs[1]
broken = dict(n, authority=[(t, o, d.replace('Q5982F1NULMKURGEEO19QK63KTLT90HQ', 'Q597PF96F0QK4P2LVCNVND7I5F4KOMOQ'))
                            for t, o, d in n['authority']])
check('com: 次のハッシュを手前にずらすと不成立', m.classify(broken)['proof']['ok'], False)
broken = dict(n, qname='zz-ac5net-nx-20261119.com.')
check('com: 別の名前には同じ 3 本が使えない', m.classify(broken)['proof']['ok'], False)

# 表示が例外なく最後まで出ること
buf = io.StringIO()
for p, n in pairs:
    m.report(p, n, buf)
check('report が 37 ゾーン分出る', buf.getvalue().count('問い合わせ :'), 37)
check('NG が 1 件も無い', '[NG]' in buf.getvalue(), False)

print()
if fails:
    print('%d / %d failed' % (len(fails), count))
    raise SystemExit(1)
print('all %d passed' % count)
