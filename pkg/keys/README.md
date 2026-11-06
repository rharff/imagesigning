# `keys`

The `keys` package creates and reads ECDSA P-256 and ML-DSA-65 key pairs used
by `imgsign`. ECDSA keys use PKCS#8/PKIX PEM encoding. ML-DSA-65 keys use
binary key encodings inside algorithm-specific PEM blocks.

## Main functions

- `Generate()` creates a new ECDSA P-256 private key (the default).
- `GenerateAlgorithm("ecdsa")` or `GenerateAlgorithm("mldsa65")` selects the
  key algorithm explicitly.
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
verify signatures. A private key's algorithm is detected from its PEM type;
callers must use the same algorithm when signing or verification fails with
an explicit algorithm mismatch error.
