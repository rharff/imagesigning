# `store`

The `store` package is the boundary between signing/verification logic and an
image registry. It defines the minimal operations needed by both workflows
and provides an ORAS registry implementation.

## `Store` interface

- `Resolve(ctx, ref)` returns the immutable image digest and lowercase
  repository name.
- `PushSignature(ctx, repo, subjectDigest, payload, sigB64)` stores a signature
  for the image identified by `subjectDigest`.
- `ListSignatures(ctx, repo, subjectDigest)` returns all candidate referrers.

`Candidate.Foreign` marks a referrer that exists but does not use the imgsign
signature format. This distinction lets the verifier report
`unsupported_signature` instead of `no_signature`.

## OCI/ORAS representation

`ORASStore` stores signatures as OCI 1.1 referrers:

- Artifact type: `application/vnd.imgsign.signature.v1`
- Payload media type: `application/vnd.imgsign.payload.v1+json`
- Signature annotation: `io.imgsign.signature`

The payload is pushed as a layer. The base64 signature is stored as that
layer's annotation, and an OCI manifest points to the signed image through its
`subject` descriptor.

```go
registryStore := store.NewORASStore()
digest, repo, err := registryStore.Resolve(ctx, imageRef)
candidates, err := registryStore.ListSignatures(ctx, repo, digest)
```

`ORASStore` caches remote repositories by registry/repository name. It uses
`GHCR_USER` and `GHCR_TOKEN` when both are set; otherwise it attempts to use
the local Docker credential store.
