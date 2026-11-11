# Signer container

Image `imgsign-signer:dev` mengemas CLI `imgsign` tanpa membawa private key
atau token ke dalam image. Build image secara lokal:

```bash
make signer-image
```

## Pemakaian

Semua contoh berikut memakai image lokal dan menjalankan CLI melalui
`ENTRYPOINT` image.

### Membuat keypair

Simpan keypair pada direktori host yang di-mount ke container:

```bash
mkdir -p ./keys
docker run --rm \
  -v "$PWD/keys:/keys" \
  imgsign-signer:dev keygen --alg ecdsa --out-dir /keys
```

Gunakan `--alg mldsa65` untuk membuat keypair ML-DSA-65. Jangan menimpa file
key yang sudah ada.

### Sign

Image yang ditandatangani harus berupa reference yang sudah menunjuk digest,
dengan bentuk `repo@sha256:digest`, bukan tag saja:

```bash
docker run --rm \
  -e GHCR_USER \
  -e GHCR_TOKEN \
  -e IMGSIGN_PRIVATE_KEY \
  imgsign-signer:dev sign \
  --alg ecdsa ghcr.io/owner/app@sha256:<digest>
```

`IMGSIGN_PRIVATE_KEY` berisi PEM private key. `GHCR_USER` dan `GHCR_TOKEN`
berisi kredensial GHCR dengan permission yang sesuai. Bentuk `-e NAMA` tanpa
nilai meneruskan nilai environment host ke container tanpa menuliskan nilainya
di command atau log. Pastikan environment tersebut sudah tersedia di proses
yang menjalankan `docker run`.

### Verify

Public key dapat di-mount read-only dari host:

```bash
docker run --rm \
  -e GHCR_USER \
  -e GHCR_TOKEN \
  -v "$PWD/keys:/keys:ro" \
  imgsign-signer:dev verify \
  --alg ecdsa --pub /keys/pub.pem \
  ghcr.io/owner/app@sha256:<digest>
```

Exit code `0` berarti valid. Penolakan signature menghasilkan exit code `1`,
sedangkan error operasional menghasilkan exit code `2`.

## Contoh langkah shell Jenkins

Jenkins harus menyediakan `GHCR_USER`, `GHCR_TOKEN`, dan
`IMGSIGN_PRIVATE_KEY` sebagai environment/credential binding pada shell step.
Jangan menulis nilainya ke Jenkinsfile, command line, atau log. Contoh:

```sh
IMAGE_DIGEST='ghcr.io/owner/app@sha256:<digest>'

docker run --rm \
  -e GHCR_USER \
  -e GHCR_TOKEN \
  -e IMGSIGN_PRIVATE_KEY \
  imgsign-signer:dev sign --alg ecdsa "$IMAGE_DIGEST"
```

Nilai `IMAGE_DIGEST` pada contoh harus berbentuk `repo@sha256:digest`; jangan
menggunakan tag seperti `ghcr.io/owner/app:latest`, karena signature harus
terikat pada digest image yang tepat.
