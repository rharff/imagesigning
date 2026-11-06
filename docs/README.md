# imgsign

`imgsign` adalah library Go dan CLI untuk menandatangani digest container
image menggunakan ECDSA P-256 atau ML-DSA-65. Signature disimpan sebagai OCI 1.1 referrer,
bukan sebagai tag `.sig`, sehingga verifier selalu menemukan signature dari
digest image yang sedang diperiksa.

## Build

```bash
go build -o imgsign ./cmd/imgsign
```

## Bantuan CLI

Tampilkan semua command dan contoh penggunaan:

```bash
./imgsign -h
```

Untuk melihat flag command tertentu:

```bash
./imgsign keygen -h
./imgsign sign -h
./imgsign verify -h
./imgsign verify-detail -h
```

## Membuat keypair

```bash
./imgsign keygen --alg ecdsa --out-dir ./keys
```

Gunakan `--alg mldsa65` untuk ML-DSA-65. Perintah ini membuat `priv.pem`
dan `pub.pem` dengan format PEM sesuai algoritmanya. File yang sudah ada
tidak ditimpa.

## Konfigurasi registry

Untuk GHCR, login dengan Docker terlebih dahulu:

```bash
docker login ghcr.io
```

Alternatifnya, berikan credential hanya pada environment proses (jangan
ditulis ke source code atau commit):

```bash
export GHCR_USER="username-github"
export GHCR_TOKEN="github_pat_..."
```

PAT memerlukan permission `read:packages` untuk verify dan `write:packages`
untuk sign. `GHCR_USER` dan `GHCR_TOKEN` digunakan bersama; jika tidak ada,
program mencoba credential store Docker.

Private key dapat diberikan sebagai path:

```bash
./imgsign sign --alg ecdsa --key ./keys/priv.pem ghcr.io/owner/app:latest
```

Flag `--alg` default-nya `ecdsa`. Algoritma pada flag harus sama dengan
algoritma key. Contoh, key ECDSA dengan `--alg mldsa65` ditolak dengan error
`algorithm mismatch: private key is ecdsa, but signing requested mldsa65`.

Untuk CI yang menyediakan isi PEM melalui environment, `IMGSIGN_PRIVATE_KEY`
boleh berisi langsung isi PEM (atau path file PEM). Contoh aman:

```bash
export IMGSIGN_PRIVATE_KEY="$(cat ./keys/priv.pem)"
./imgsign sign ghcr.io/owner/app:latest
```

Jangan menaruh nilai ini di repository, command history yang dibagikan, atau
log CI.

Output sign:

```text
signed ghcr.io/owner/app@sha256:...
```

## Verify

```bash
./imgsign verify --alg ecdsa --pub ./keys/pub.pem ghcr.io/owner/app:latest
```

Untuk mengumpulkan metrik tanpa mengubah command `verify`, gunakan command
terpisah berikut:

```bash
./imgsign verify-detail --alg ecdsa --pub ./keys/pub.pem ghcr.io/owner/app:latest
```

Output berupa JSON dan mencakup ukuran public key, payload, signature raw dan
base64, manifest/config/layer OCI, jumlah serta status candidate, dan durasi
resolve/list/verifikasi. Ukuran private key dapat dicatat tanpa mencetak
isinya dengan flag opsional:

```bash
./imgsign verify-detail --alg ecdsa --pub ./keys/pub.pem \
  --priv ./keys/priv.pem ghcr.io/owner/app:latest
```

`verify-detail` mempertahankan exit code validasi: `0` untuk valid, `1` untuk
rejection, dan `2` untuk error operasional.

Verifier meresolve tag ke digest terlebih dahulu, mengambil referrer dengan
`artifactType` milik imgsign, lalu memverifikasi bytes layer persis seperti
yang tersimpan. Signature yang tidak cocok diabaikan. Hasil `REJECT` memiliki
exit code 1:

- `no_signature`: tidak ada referrer imgsign
- `unsupported_signature`: terdapat referrer signature, tetapi formatnya bukan
  imgsign, misalnya signature Cosign
- `bad_signature`: tidak ada signature yang lolos verifikasi public key
- `algorithm_mismatch`: signature memakai algoritma berbeda dari `--alg`
- `digest_mismatch`: payload menunjuk digest berbeda
- `repo_mismatch`: payload menunjuk repository berbeda

Error jaringan, autentikasi, key, atau argumen menghasilkan exit code 2 dan
tidak pernah dianggap valid.

## Library

Package `pkg/verifier` tidak bergantung pada implementasi registry. Integrasi
lain dapat menyediakan `store.Store` sendiri:

```go
err := verifier.Verify(ctx, myStore, publicKey, keys.ECDSA, imageRef)
```

Package utama:

- `pkg/keys`: generate, simpan, dan load PEM
- `pkg/payload`: payload JSON deterministik dan domain separation
- `pkg/store`: interface store dan implementasi oras-go/registry
- `pkg/signer`: resolve, sign, dan push signature
- `pkg/verifier`: validasi signature yang dapat dipakai deploy gate/webhook

## Pengembangan

Validasi kompilasi lokal:

```bash
go test ./...
```

Tes integrasi GHCR membutuhkan akses registry. Jalankan dari mesin kamu dengan
credential berikut; secret tidak perlu dikirim ke chat:
gunakan repository uji terpisah dan environment berikut:

```bash
export IMGSIGN_TEST_REPO=ghcr.io/<owner>/imgsign-test
export GHCR_USER=<username>
export GHCR_TOKEN=<PAT>
```

Implementasi menggunakan `oras.land/oras-go/v2`; library tersebut menangani
listing semua referrer OCI 1.1 dan fallback referrers-tag schema ketika registry
belum menyediakan endpoint native. Semua referrer diperiksa agar verifier dapat
membedakan `no_signature` dari `unsupported_signature`. Signature Cosign tidak
diverifikasi oleh imgsign karena payload, artifact type, dan domain separation
Cosign berbeda.
