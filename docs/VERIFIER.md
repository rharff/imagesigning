# Verifier admission integration

`imgsign-verifier` adalah verifier image yang diintegrasikan sebagai Kubernetes
Validating Admission Webhook. Komponen ini memverifikasi semua image pada Pod
menggunakan `pkg/verifier`. Verifier hanya menerima image berbentuk
`repo@sha256:digest`; tag seperti `repo:latest` ditolak. Verifier tidak
mengubah Pod.

## Build image

```bash
make verifier-image
```

Image lokalnya adalah `imgsign-verifier:dev`. Image bersifat static dan berjalan
sebagai user non-root. TLS certificate, private key TLS, public key imgsign,
dan credential registry harus dipasang atau diberikan saat deployment; tidak
ada secret yang dimasukkan ke image.

## Environment

| Nama | Arti |
|---|---|
| `TLS_CERT_FILE` | Path certificate TLS server di dalam container. |
| `TLS_KEY_FILE` | Path private key TLS server di dalam container. |
| `IMGSIGN_PUBLIC_KEY_FILE` | Path public key imgsign PEM di dalam container. |
| `GHCR_USER` | Username GHCR untuk akses registry. |
| `GHCR_TOKEN` | PAT/token GHCR untuk akses registry. |
| `PORT` | Port HTTPS listener; default `8443`. |

`GHCR_USER` dan `GHCR_TOKEN` dibaca oleh store registry. Jangan mencetak
nilainya ke log atau memasukkannya ke image.

## TLS

Certificate server harus memiliki SAN yang sama dengan alamat Service yang
dipakai verifier. Contoh untuk Service `imgsign-verifier` pada namespace
`security`:

```bash
openssl req -x509 -newkey rsa:4096 -nodes -days 365 \
  -keyout verifier.key -out verifier.crt \
  -subj '/CN=imgsign-verifier.security.svc' \
  -addext 'subjectAltName=DNS:imgsign-verifier.security.svc,DNS:imgsign-verifier.security.svc.cluster.local'
```

`caBundle` pada `ValidatingWebhookConfiguration` harus berisi CA yang
menandatangani certificate tersebut, dalam base64. Certificate self-signed
di atas dapat dipakai sebagai CA untuk referensi lokal:

```bash
base64 -w0 verifier.crt
```

Untuk produksi, gunakan CA internal atau cert-manager sesuai kebijakan
cluster. Secret TLS dan public key dipasang sebagai volume read-only.

## Deployment Kubernetes

Manifest Deployment, Service, dan `ValidatingWebhookConfiguration` tersedia
terpisah di folder [k8s/](../k8s/). Manifest tersebut memakai image lokal
`imgsign-verifier:dev`, Secret untuk TLS/public key/GHCR, `failurePolicy: Fail`,
operasi Pod `CREATE` dan `UPDATE`, serta namespace berlabel
`imgsign-enforce=enabled`. Ikuti [k8s/README.md](../k8s/README.md) sebelum
menerapkannya.

## Keputusan dan log

Request memiliki batas waktu verifikasi 8 detik. Pod hanya diizinkan jika
semua image dari `containers`, `initContainers`, dan `ephemeralContainers`
valid. Tag ditolak dengan `tag_not_allowed`; penolakan verifier memakai kode
alasan seperti `no_signature`, `bad_signature`, `digest_mismatch`, atau
`repo_mismatch`; error registry, timeout, dan autentikasi menjadi
`verify_error`. Semua keputusan ditolak (fail-closed) dan pesan response
memuat image serta kode alasan.

Verifier menulis satu JSON object per keputusan ke stdout:

```json
{"time":"2026-11-11T04:00:00Z","namespace":"prod","pod":"api","image":"ghcr.io/acme/app@sha256:...","decision":"allow","reason":"valid","duration_ms":42}
```

Gunakan log collector Kubernetes atau `kubectl logs` untuk membacanya. Field
`image`, `decision`, dan `reason` dapat dipakai untuk audit; token dan public
key tidak pernah ditulis.
