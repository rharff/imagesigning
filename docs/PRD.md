# PRD: Custom Image Signer + Verifier (`imgsign`)

## 1. Tujuan
Menandatangani digest container image dengan ECDSA P-256 atau ML-DSA-65 dan menyimpan
signature di GHCR sebagai OCI 1.1 referrer dari image tersebut. Verifier
mengambil signature dari GHCR dan memverifikasinya dengan public key.
Dibangun sebagai library Go + CLI. Verifier harus berupa package terpisah
agar nanti bisa dipakai ulang oleh deploy gate atau webhook.

## 2. Asumsi Keamanan
- Penyerang menguasai registry (push, overwrite tag, hapus/ganti artifact,
  menambah referrer palsu).
- Penyerang tidak menguasai private key.
- Verifier hanya memercayai public key yang diberikan, bukan signature
  apa pun yang ada di registry.

## 3. Ruang Lingkup
In scope: keygen, sign, verify, tes integrasi ke GHCR.
Out of scope: webhook K8s (kita kembangkan setelah ini berhasil), keyless, transparency log,
multi-signature, metrik internal (benchmark diukur dari luar).

## 4. Stack
- Go (versi stabil terbaru). Tanpa implementasi kripto sendiri.
- stdlib: `crypto/ecdsa`, `crypto/elliptic`, `crypto/sha256`, `crypto/x509`,
  `encoding/pem`, `encoding/json`.
- `github.com/cloudflare/circl/sign/mldsa/mldsa65` untuk ML-DSA-65.
- `oras.land/oras-go/v2` untuk semua operasi registry (resolve, push
  manifest ber-subject, list referrers dengan fallback otomatis ke
  referrers tag schema).
- Auth: docker credential store (`docker login ghcr.io`) atau env
  `GHCR_USER` + `GHCR_TOKEN` (PAT scope read/write:packages).
  Beri tau aku dimana harus aku letakkan username dan PAT nya nanti

## 5. Struktur Repo
```
signing/
  cmd/imgsign/       # keygen | sign | verify
  pkg/keys/          # generate, load private/public key
  pkg/payload/       # struct + serialisasi deterministik
  pkg/store/         # interface Store + implementasi oras (GHCR)
  pkg/signer/
  pkg/verifier/      # dipakai ulang oleh webhook nanti
  test/
    unit/            # tanpa jaringan
    integration/     # langsung ke GHCR
```

`pkg/store` berupa interface supaya signer dan verifier tidak bergantung
langsung pada oras:
```go
type Store interface {
    Resolve(ctx, ref) (digest string, repo string, err error)
    PushSignature(ctx, repo, subjectDigest string, payload []byte, sigB64 string) error
    ListSignatures(ctx, repo, subjectDigest string) ([]Candidate, error)
}
type Candidate struct {
    Payload []byte // isi layer persis seperti tersimpan
    SigB64  string // dari annotation layer
}
```

## 6. Keputusan Desain

### 6.1 Kunci
- ECDSA P-256 atau ML-DSA-65. Default tetap ECDSA. Tipe key ditentukan saat
  `keygen` dan harus sama dengan `--alg` saat `sign` atau `verify`.
- `keygen` menulis `priv.pem` (mode 0600) dan `pub.pem`; menolak menimpa
  file yang sudah ada.
- `sign` membaca private key dari `--key <path>` atau env
  `IMGSIGN_PRIVATE_KEY` (isi PEM, untuk Jenkins). Jika keduanya ada,
  `--key` menang.

### 6.2 Payload
JSON, urutan field tetap, tanpa whitespace, dibangun dengan serialisasi
manual atau struct berurutan (bukan map):
{"v":2,"alg":"ecdsa","repo":"ghcr.io/owner/app","digest":"sha256:<hex>","iat":1730000000}
- `repo` dan `digest` wajib. Repo ditulis lowercase tanpa tag dan tanpa
  digest. Ini mengikat signature ke repository dan digest.
- `iat` hanya metadata, tidak divalidasi.
- Bytes yang ditandatangani: `"imgsign.v1\n" + payloadJSON`
  (domain separation).
- Signature ECDSA memakai `ecdsa.SignASN1` atas SHA-256; ML-DSA-65 memakai
  format native ML-DSA. Keduanya disimpan base64 standar.
- Verifier memverifikasi terhadap bytes layer persis seperti tersimpan,
  TIDAK re-serialisasi hasil parse. Setelah signature lolos baru payload
  di-parse.

### 6.3 Penyimpanan signature (OCI 1.1 Referrers)
Signature adalah OCI image manifest dengan:
- `subject` = descriptor manifest image yang ditandatangani
- `artifactType` = `application/vnd.imgsign.signature.v1`
- config: `application/vnd.oci.empty.v1+json` (descriptor kosong)
- 1 layer: payloadJSON, mediaType `application/vnd.imgsign.payload.v1+json`
- annotation pada layer: `io.imgsign.signature` = signature base64
- Tidak ada tag `.sig`. Lokasi ditemukan lewat referrers dari digest image.
- Jangan memakai artifactType, mediaType, atau annotation milik Cosign.
- Sign tidak mengecek duplikasi; verifier yang menentukan validitas.
- oras-go menangani pembaruan index fallback jika GHCR tidak punya
  endpoint `/referrers/` native.

### 6.4 Digest
- Input boleh tag atau digest. Selalu di-resolve ke digest manifest
  (image index untuk multi-arch), dan digest itu yang ditandatangani.
- Jangan hash biner layer.
- Setelah resolve, seluruh langkah berikutnya memakai digest, bukan tag.

## 7. Alur Sign
1. Resolve ref ke digest manifest (HEAD ke registry).
2. Susun payload, serialisasi deterministik.
3. Hitung SHA-256 atas `"imgsign.v1\n" + payload`, tandatangani.
4. Push manifest signature ber-`subject` ke repo yang sama.
5. Cetak ke stdout: `signed <repo>@<digest>`.

## 8. Alur Verify
Input: image ref, public key.
1. Resolve ref ke digest dari registry (bukan dari payload).
2. List referrers digest tersebut, filter `artifactType` =
   `application/vnd.imgsign.signature.v1`. Kosong -> `no_signature`.
3. Untuk setiap kandidat: batasi ukuran payload (maks 4 KiB), verifikasi
   signature atas bytes layer dengan public key. Yang gagal diabaikan.
   Tidak ada yang lolos -> `bad_signature`.
4. Untuk kandidat yang signature-nya lolos: `digest` payload harus sama
   dengan hasil langkah 1 (`digest_mismatch`), lalu `repo` harus sama
   dengan repo ref (`repo_mismatch`).
5. Valid jika minimal satu kandidat lolos semua cek. Jika tidak ada,
   kembalikan alasan dari kandidat yang paling jauh lolos
   (urutan: `bad_signature` < `repo_mismatch` < `digest_mismatch`
   tidak berlaku; cukup kembalikan alasan kandidat pertama yang
   signature-nya sah).
Referrer palsu dari penyerang diabaikan karena tidak lolos public key.

Exit code CLI:
- 0 = valid
- 1 = ditolak (cetak `REJECT <kode>` ke stderr; kode: `no_signature`,
  `bad_signature`, `algorithm_mismatch`, `digest_mismatch`, `repo_mismatch`)
- 2 = error operasional (jaringan, auth, argumen, key tidak terbaca).
  Error operasional TIDAK BOLEH dianggap valid.

## 9. CLI
```
imgsign keygen --alg ecdsa --out-dir ./keys
imgsign keygen --alg mldsa65 --out-dir ./keys-mldsa
imgsign sign   --alg ecdsa --key priv.pem <image-ref>
imgsign verify --alg ecdsa --pub pub.pem  <image-ref>
```

## 10. Pengujian

### 10.1 Unit (tanpa jaringan)
- keys: generate, simpan, muat ulang, tolak file yang sudah ada.
- payload: input sama menghasilkan bytes identik (determinisme), urutan
  field tetap, repo di-lowercase.
- signer/verifier dengan Store palsu di memori: sign lalu verify valid,
  kunci salah, payload diubah, signature rusak.

### 10.2 Integrasi (langsung ke GHCR)
Konfigurasi lewat env, dan tes di-skip dengan pesan jelas jika tidak ada:
- `IMGSIGN_TEST_REPO` (contoh `ghcr.io/<owner>/imgsign-test`)
- `GHCR_USER`, `GHCR_TOKEN`
Fixture dibuat oleh tes sendiri lewat oras: push image OCI minimal
(config kosong + 1 layer berisi byte acak) ke tag unik per run
(`t-<timestamp>-<n>`), sehingga digest selalu baru. Tes tidak menghapus
artifact (butuh scope delete:packages); bersihkan manual berkala.

Skenario wajib:
1. Sign lalu verify: valid.
2. Image tanpa signature: `no_signature`.
3. Kunci salah (sign dengan keypair B, verify dengan public A):
   `bad_signature`.
4. Payload diubah: push referrer baru dengan layer payload dimodifikasi
   dan signature asli: `bad_signature`.
5. Signature repo lain: image identik di-push ke dua repo (A dan B),
   referrer sah dari A disalin ke B: `repo_mismatch`.
6. Signature image lain: referrer sah milik image X dipasang dengan
   `subject` image Y: `digest_mismatch`.
7. Tag dipindah: tanda tangani tag `t1`, lalu arahkan `t1` ke image
   lain; verify `t1` menolak (image baru tidak punya signature sah).
8. Referrer palsu berdampingan dengan yang asli: verify tetap valid.
9. Referrer palsu saja (ditandatangani kunci penyerang): `bad_signature`.
10. Error operasional (token salah atau repo tidak ada): exit code 2,
    bukan 0.
Catat di output tes apakah GHCR melayani referrers lewat API native atau
fallback tag.

## 11. Kriteria Penerimaan
- [ ] Semua tes unit lulus tanpa jaringan.
- [ ] Sepuluh skenario integrasi lulus terhadap GHCR sungguhan.
- [ ] Payload sama menghasilkan bytes sama (tes determinisme).
- [ ] `verify` tidak pernah mengembalikan 0 saat terjadi error operasional.
- [ ] Sign dari satu mesin dan verify dari mesin lain (hanya public key
      dan akses GHCR) berhasil.
- [ ] README singkat: cara keygen, sign, verify, dan menjalankan tes.
