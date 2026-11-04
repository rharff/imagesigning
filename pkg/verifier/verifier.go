package verifier

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"

	"imgsign/pkg/payload"
	"imgsign/pkg/store"
)

const (
	NoSignature          = "no_signature"
	BadSignature         = "bad_signature"
	DigestMismatch       = "digest_mismatch"
	RepoMismatch         = "repo_mismatch"
	UnsupportedSignature = "unsupported_signature"
)

type Rejection struct{ Code string }

func (e *Rejection) Error() string { return e.Code }

func Verify(ctx context.Context, s store.Store, key *ecdsa.PublicKey, ref string) error {
	digest, repo, err := s.Resolve(ctx, ref)
	if err != nil {
		return err
	}
	candidates, err := s.ListSignatures(ctx, repo, digest)
	if err != nil {
		return err
	}
	if len(candidates) == 0 {
		return &Rejection{NoSignature}
	}
	hasImgSignCandidate := false
	for _, c := range candidates {
		if c.Foreign {
			continue
		}
		hasImgSignCandidate = true
		if len(c.Payload) > 4096 {
			continue
		}
		sig, err := base64.StdEncoding.DecodeString(c.SigB64)
		if err != nil {
			continue
		}
		sum := sha256.Sum256(payload.SigningBytes(c.Payload))
		if !ecdsa.VerifyASN1(key, sum[:], sig) {
			continue
		}
		p, err := payload.Parse(c.Payload)
		if err != nil {
			return &Rejection{BadSignature}
		}
		if p.Digest != digest {
			return &Rejection{DigestMismatch}
		}
		if p.Repo != repo {
			return &Rejection{RepoMismatch}
		}
		return nil
	}
	if !hasImgSignCandidate {
		return &Rejection{UnsupportedSignature}
	}
	return &Rejection{BadSignature}
}

func Code(err error) string {
	var rejection *Rejection
	if errors.As(err, &rejection) {
		return rejection.Code
	}
	return fmt.Sprintf("error: %v", err)
}
