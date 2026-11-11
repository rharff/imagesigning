.PHONY: signer-image verifier-image

signer-image:
	docker build -f Dockerfile.signer -t imgsign-signer:dev .

verifier-image:
	docker build -f Dockerfile.verifier -t imgsign-verifier:dev .
