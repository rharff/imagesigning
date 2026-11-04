package signer

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	"imgsign/pkg/payload"
	"imgsign/pkg/store"
)

func Sign(ctx context.Context, s store.Store, key *ecdsa.PrivateKey, ref string, now time.Time) (string, error) {
	digest, repo, err := s.Resolve(ctx, ref)
	if err != nil {
		return "", err
	}
	p, err := payload.New(repo, digest, now.Unix())
	if err != nil {
		return "", err
	}
	raw, err := p.Marshal()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(payload.SigningBytes(raw))
	sig, err := ecdsa.SignASN1(rand.Reader, key, sum[:])
	if err != nil {
		return "", fmt.Errorf("sign payload: %w", err)
	}
	sigB64 := base64.StdEncoding.EncodeToString(sig)
	if err := s.PushSignature(ctx, repo, digest, raw, sigB64); err != nil {
		return "", err
	}
	return repo + "@" + digest, nil
}
