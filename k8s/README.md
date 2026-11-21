# Deploy Verifier

Jalankan semua perintah dari root repository.

## 1. Buat namespace

```bash
kubectl create namespace security --dry-run=client -o yaml | kubectl apply -f -
```

## 2. Buat certificate TLS

```bash
cd k8s

openssl req -x509 -newkey rsa:4096 -nodes -days 365 \
  -keyout verifier.key -out verifier.crt \
  -subj '/CN=imgsign-verifier.security.svc' \
  -addext 'subjectAltName=DNS:imgsign-verifier.security.svc,DNS:imgsign-verifier.security.svc.cluster.local'
```

## 3. Buat Secret TLS

```bash
kubectl -n security create secret tls imgsign-verifier-tls \
  --cert=verifier.crt \
  --key=verifier.key \
  --dry-run=client -o yaml | kubectl apply -f -
```

## 4. Buat Secret public key

```bash
kubectl -n security create secret generic imgsign-public-key \
  --from-file=pub.pem=../keys/pub.pem \
  --dry-run=client -o yaml | kubectl apply -f -
```

Gunakan file `pub.pem` yang cocok dengan private key yang dipakai untuk
menandatangani image.

## 5. Buat Secret credential registry

Isi credential GHCR terlebih dahulu:

```bash
export GHCR_USER="USERNAME_GITHUB"
export GHCR_TOKEN="PAT_GITHUB"

kubectl -n security create secret generic ghcr-credentials \
  --from-literal=username="$GHCR_USER" \
  --from-literal=token="$GHCR_TOKEN" \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl -n security create secret docker-registry ghcr-pull \
  --docker-server=ghcr.io \
  --docker-username="$GHCR_USER" \
  --docker-password="$GHCR_TOKEN" \
  --dry-run=client -o yaml | kubectl apply -f -
```

## 6. Siapkan image verifier

Pakai image registry yang tersedia pada cluster:

```yaml
image: ghcr.io/rharff/imagesigning/verifier:1
```

Atau build image lokal dari root repository:

```bash
cd ..
make verifier-image
```

Untuk cluster `kind`:

```bash
kind load docker-image imgsign-verifier:dev
```

Ubah `image` pada `k8s/deployment.yaml` menjadi
`imgsign-verifier:dev`.

## 7. Generate manifest webhook dengan CA bundle

```bash
cd k8s

CA_BUNDLE="$(base64 -w0 verifier.crt)"
sed "s|REPLACE_WITH_BASE64_CA|${CA_BUNDLE}|g" \
  validatingwebhookconfiguration.yaml \
  > /tmp/imgsign-validatingwebhookconfiguration.yaml
```

## 8. Apply resource

```bash
kubectl apply -f deployment.yaml
kubectl apply -f service.yaml

kubectl -n security rollout status deployment/imgsign-verifier
kubectl apply -f /tmp/imgsign-validatingwebhookconfiguration.yaml
```

## 9. Aktifkan enforcement

```bash
kubectl label namespace <namespace> imgsign-enforce=enabled
```

Contoh:

```bash
kubectl label namespace prod imgsign-enforce=enabled
```

## 10. Verifikasi

```bash
kubectl -n security get pods,service,secrets
kubectl -n security rollout status deployment/imgsign-verifier
kubectl get validatingwebhookconfiguration imgsign-verifier
kubectl -n security logs deployment/imgsign-verifier --tail=50
```
