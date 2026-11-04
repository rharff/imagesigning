# `keys`

The `keys` package creates and reads the ECDSA P-256 key pair used by
`imgsign`. Private keys are encoded as PKCS#8 inside PEM, while public keys
are encoded as PKIX inside PEM.

## Main functions

- `Generate()` creates a new ECDSA P-256 private key.
- `SavePair(dir, privateKey)` writes `priv.pem` and `pub.pem`. The directory
  is created with mode `0700`; the private key is written with mode `0600`.
  Existing files are never overwritten.
- `LoadPrivate(path)` and `LoadPublic(path)` read keys from PEM files.
- `ParsePrivate(data)` parses private-key PEM bytes already held in memory.

Both parsing paths reject keys that are not ECDSA P-256. Parsing errors are
returned to the caller rather than silently falling back to another key type.

## Example

```go
key, err := keys.Generate()
if err != nil {
    return err
}
if err := keys.SavePair("./keys", key); err != nil {
    return err
}

privateKey, err := keys.LoadPrivate("./keys/priv.pem")
publicKey, err := keys.LoadPublic("./keys/pub.pem")
```

Keep `priv.pem` secret. The public key can be distributed to systems that
verify signatures.
