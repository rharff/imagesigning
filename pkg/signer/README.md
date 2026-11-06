# `signer`

The `signer` package coordinates image resolution, payload creation, ECDSA or
ML-DSA-65 signing, and signature storage. It does not know how a registry works; that
responsibility belongs to the `store.Store` implementation.

## Signing flow

`Sign(ctx, store, privateKey, algorithm, ref, now)` performs these steps:

1. Resolves `ref` (for example, `ghcr.io/acme/app:latest`) to an immutable
   digest and canonical repository name.
2. Builds a version 1 payload containing the repository, digest, and `now`.
3. Marshals the payload and signs the domain-separated bytes with the selected
   algorithm.
4. Creates an algorithm-specific signature using the supplied private key.
5. Base64-encodes the signature and calls `PushSignature`.
6. Returns `repo@digest` for the signed image.

```go
signedRef, err := signer.Sign(
    ctx,
    store.NewORASStore(),
    privateKey, keys.ECDSA,
    "ghcr.io/acme/app:latest",
    time.Now(),
)
```

The timestamp is passed explicitly so callers can control it in tests or
other deterministic workflows. The package returns errors from resolution,
payload validation, signing, and storage.

## Implementing another backend

Implement `store.Store` and pass it to `Sign`. The implementation must resolve
the same canonical repository and digest that it later uses to find and store
the signature.
