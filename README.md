# nsec3check

DNSSEC の「その名前は存在しない」という証明（**NSEC / NSEC3**）を読み、**RFC 5155 の式で検算**するスクリプトです。
NSEC3 のパラメータを **RFC 9276** の推奨（`1 0 0 -`）に照らし、**RFC 9824（Compact Denial of Existence）** の応答も判別します。
Python 標準ライブラリだけで動き、外部パッケージのインストールは不要です。

## 使い方

```
git clone https://github.com/ac5net/nsec3check.git
cd nsec3check
python3 nsec3check.py <ゾーン名> [<ゾーン名> ...]
```

例

```
python3 nsec3check.py jprs.jp ietf.org
python3 nsec3check.py --fixture fixtures/live-2026-11-18.txt
python3 nsec3check.py --hash example aabbccdd 12
```

ゾーン名を渡すと、頂点の NSEC3PARAM と、その場で作った存在しない名前の A を DoH（dns.google、`do=1`）で引きます。
`--fixture` はネットワークに出ず、保存済みの応答を読みます。`--hash 名前 ソルト 反復回数` は NSEC3 ハッシュだけを計算します。

RRSIG の署名検証はしません。リゾルバが返した AD ビットを表示するだけです。

## 何をしているか

- NSEC3 ハッシュの計算（RFC 5155 5 節。ワイヤ形式の名前 + ソルトの SHA-1、反復回数は「追加の」回数、表記は base32hex）
- 8.3 節の手順で closest encloser を特定し、next closer とワイルドカードが NSEC3 に覆われているかを確かめる（8.4 節）
- next closer を覆う NSEC3 が Opt-Out かどうかを見て、AD ビットが立ってよい応答かを示す（9.2 節）
- NSEC の応答は RFC 4034 6.1 の正規順序で判定する（連鎖の最後の 1 本の回り込みを含む）
- 問い合わせ名と同名の NSEC / NSEC3 が返る応答を、NXNAME（型 128）の有無で分ける（RFC 9824）
- NSEC3 のパラメータを RFC 9276 3.1 に照らす（反復 0 は MUST、ソルトは SHOULD NOT、小さなゾーンの Opt-Out は NOT RECOMMENDED）

## 実測（2026年11月18日）

ルート、TLD 24 個、署名済みドメイン 11 個、未署名の参照 1 個に、存在しない名前を問い合わせた結果です。

- TLD 24 個のうち **NSEC3 が 21、NSEC が 3**（se、ch、br）。ルートも NSEC
- NSEC3 の 21 個のうち **`1 0 0 -` は 14 個**。反復が 0 でないのは 4 個（dev、app、google が 1、cn が 10）
- **Opt-Out は 16 個で、その配下の NXDOMAIN 応答はすべて AD=0**（RFC 5155 9.2）。Opt-Out でない NSEC3 と NSEC はすべて AD=1
- 署名済みドメイン 11 個のうち、存在しない名前に NOERROR を返したのが 4 個
  （NXNAME 付きの Compact Denial 2、NXNAME の無い同名 NSEC 1、ワイルドカードで A が返るもの 1）
- NSEC3 の 27 ゾーンと NSEC の 5 ゾーンは、応答に入っていたレコードだけで不在が成り立った

`fixtures/live-2026-11-18.txt` はその日に dns.google から取得した 74 件の応答です（RRSIG は省略）。

## テスト

```
python3 test_nsec3check.py
```

ネットワークに出ないのでオフラインで実行できます。RFC 5155 Appendix A・B のハッシュ値 16 個、B.1（Name Error）・B.2（No Data）・B.2.1（Empty Non-Terminal）の応答例、
RFC 9824 3.1 節と 4 節の例、RFC 4034 6.1 節の並び順の例、実データ 37 ゾーンを 114 件のアサーションで確認します。

## 解説記事

RFC の要件の読み合わせ、実測の詳細、落とし穴の経緯はブログに書いています。

https://ac-5.net/security/nsec3-denial-of-existence-rfc9276-check/

## ライセンス

MIT
