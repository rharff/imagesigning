# `payload`

The `payload` package defines the signed message format. It is deliberately
independent of a registry implementation so the same bytes can be signed,
stored, and verified by different backends.

## Payload format

`New(repo, digest, iat)` normalizes the repository to lowercase and creates
version 1 of the payload:

```json
{"v":1,"repo":"ghcr.io/acme/app","digest":"sha256:...","iat":1730000000}
```

- `v` is the format version and must be `1`.
- `repo` is the registry/repository name without a tag or digest.
- `digest` identifies the exact image manifest.
- `iat` is the Unix timestamp supplied by the signer.

`New` rejects empty values and repository names containing `:` or `@`.
`Marshal` validates the required fields and produces stable JSON field order.
`Parse` validates JSON and the required version, repository, and digest fields.

## Domain separation

Signatures are made over `SigningBytes(rawPayload)`, not over the raw JSON
alone. This prepends `Domain` (`imgsign.v1\n`) to prevent the payload from
being confused with a message from another signing protocol.

```go
payload, err := payload.New(repo, digest, time.Now().Unix())
raw, err := payload.Marshal()
bytesToSign := payload.SigningBytes(raw)
```

Any verifier or alternate signer must use the exact same domain prefix and
payload bytes.
