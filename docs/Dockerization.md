cd /home/rahan/Kuliah/Eksperimen/imgae-signing

# Login ke GHCR
echo "$GHCR_TOKEN" | docker login ghcr.io -u rharff --password-stdin

# Build signer
docker build \
  -f Dockerfile.signer \
  -t ghcr.io/rharff/imagesigning/signer:latest .

# Build verifier
docker build \
  -f Dockerfile.verifier \
  -t ghcr.io/rharff/imagesigning/verifier:latest .

# Push keduanya
docker push ghcr.io/rharff/imagesigning/signer:latest
docker push ghcr.io/rharff/imagesigning/verifier:latest

# Tag & Push
docker tag imgsign-signer:dev ghcr.io/rharff/imagesigning/signer:2
docker tag imgsign-verifier:dev ghcr.io/rharff/imagesigning/verifier:2

docker push ghcr.io/rharff/imagesigning/signer:2
docker push ghcr.io/rharff/imagesigning/verifier:2