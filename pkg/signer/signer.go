package signer

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"imgsign/pkg/keys"
	"imgsign/pkg/payload"
	"imgsign/pkg/store"
)

func Sign(ctx context.Context, s store.Store, key keys.PrivateKey, algorithm string, ref string, now time.Time) (string, error) {
	if key == nil {
		return "", fmt.Errorf("private key is required")
	}
	if key.Algorithm() != algorithm {
		return "", fmt.Errorf("algorithm mismatch: private key is %s, but signing requested %s", key.Algorithm(), algorithm)
	}
	digest, repo, err := s.Resolve(ctx, ref)
	if err != nil {
		return "", err
	}
	p, err := payload.New(repo, digest, now.Unix(), algorithm)
	if err != nil {
		return "", err
	}
	raw, err := p.Marshal()
	if err != nil {
		return "", err
	}
	sig, err := key.Sign(payload.SigningBytes(raw))
	if err != nil {
		return "", fmt.Errorf("sign payload: %w", err)
	}
	sigB64 := base64.StdEncoding.EncodeToString(sig)
	if err := s.PushSignature(ctx, repo, digest, raw, sigB64, algorithm); err != nil {
		return "", err
	}
	return repo + "@" + digest, nil
}
