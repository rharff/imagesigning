# Deploy verifier

## Deploy

Siapkan image `imgsign-verifier:dev` pada node/registry cluster, lalu buat
namespace dan Secret:

```bash
kubectl create namespace security

kubectl -n security create secret tls imgsign-verifier-tls \
  --cert=verifier.crt --key=verifier.key

kubectl -n security create secret generic imgsign-public-key \
  --from-file=pub.pem

kubectl -n security create secret generic ghcr-credentials \
  --from-literal=username="$GHCR_USER" \
  --from-literal=token="$GHCR_TOKEN"
```

Isi `REPLACE_WITH_BASE64_CA` di
[validatingwebhookconfiguration.yaml](./validatingwebhookconfiguration.yaml)
dengan CA certificate sebelum apply. Jangan commit Secret atau token.

Apply resource dalam urutan berikut:

```bash
kubectl apply -f deployment.yaml
kubectl apply -f service.yaml
kubectl apply -f validatingwebhookconfiguration.yaml
```

Aktifkan enforcement pada namespace target:

```bash
kubectl label namespace <namespace> imgsign-enforce=enabled
```

Manifest memvalidasi Pod pada operasi `CREATE` dan `UPDATE`, dan menggunakan
`failurePolicy: Fail`.

## Tombol nuklir

Perintah berikut menghapus webhook dan seluruh resource verifier di namespace
`security`. Jalankan hanya jika memang ingin mematikan enforcement dan
membersihkan instalasi:

```bash
kubectl delete -f validatingwebhookconfiguration.yaml --ignore-not-found
kubectl delete -f service.yaml --ignore-not-found
kubectl delete -f deployment.yaml --ignore-not-found

kubectl -n security delete secret imgsign-verifier-tls \
  imgsign-public-key ghcr-credentials --ignore-not-found
kubectl delete namespace security --ignore-not-found
```

Opsional: jika namespace target tetap dipertahankan dan label enforcement ingin
dihapus, jalankan:

```bash
kubectl label namespace <namespace> imgsign-enforce-
```
