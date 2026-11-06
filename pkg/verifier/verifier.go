package verifier

import (
	"context"
	"errors"
	"fmt"

	"imgsign/pkg/keys"
	"imgsign/pkg/store"
)

const (
	NoSignature          = "no_signature"
	BadSignature         = "bad_signature"
	DigestMismatch       = "digest_mismatch"
	RepoMismatch         = "repo_mismatch"
	AlgorithmMismatch    = "algorithm_mismatch"
	UnsupportedSignature = "unsupported_signature"
)

type Rejection struct{ Code string }

func (e *Rejection) Error() string { return e.Code }

func Verify(ctx context.Context, s store.Store, key keys.PublicKey, algorithm string, ref string) error {
	if key == nil {
		return errors.New("public key is required")
	}
	if key.Algorithm() != algorithm {
		return fmt.Errorf("algorithm mismatch: public key is %s, but verification requested %s", key.Algorithm(), algorithm)
	}
	digest, repo, err := s.Resolve(ctx, ref)
	if err != nil {
		return err
	}
	candidates, err := s.ListSignatures(ctx, repo, digest)
	if err != nil {
		return err
	}
	return VerifyCandidates(key, algorithm, repo, digest, candidates)
}

func Code(err error) string {
	var rejection *Rejection
	if errors.As(err, &rejection) {
		return rejection.Code
	}
	return fmt.Sprintf("error: %v", err)
}
