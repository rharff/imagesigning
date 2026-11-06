# `verifier`

The `verifier` package checks whether an image has a valid imgsign signature.
It is registry-agnostic and only depends on the `store.Store` interface.

## Verification flow

`Verify(ctx, store, publicKey, algorithm, ref)`:

1. Resolves the reference to its current digest and canonical repository.
2. Lists all referrer candidates for that digest.
3. Ignores foreign signature formats.
4. Decodes the base64 signature and verifies it with the selected algorithm
   over the domain-separated payload bytes.
5. Parses the payload and checks both its digest and repository.
6. Returns `nil` after the first candidate that passes every check.

```go
if err := verifier.Verify(ctx, registryStore, publicKey, imageRef); err != nil {
    fmt.Println(verifier.Code(err))
}
```

## Rejection codes

Use `Code(err)` to obtain a stable result:

- `no_signature`: no referrers were found.
- `unsupported_signature`: referrers exist, but none use imgsign's format.
- `bad_signature`: imgsign candidates exist, but signature verification or
  payload validation failed.
- `digest_mismatch`: a valid signature refers to another image digest.
- `repo_mismatch`: a valid signature refers to another repository.

Registry, authentication, key, and other operational errors are returned as
regular errors and are not converted into a rejection code. The CLI uses
`Rejection` errors to distinguish an invalid image from an execution failure.
