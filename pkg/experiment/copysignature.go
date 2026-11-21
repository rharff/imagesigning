// Utilitas khusus pengujian skenario, bukan bagian alur produksi.
package experiment

import (
	"context"
	"errors"

	"imgsign/pkg/store"
)

// CopySignature copies existing imgsign signature artifacts from one image to
// another image in the same repository. It is intended for mismatch testing.
func CopySignature(ctx context.Context, s store.Store, fromRef, toRef string) error {
	fromDigest, fromRepo, err := s.Resolve(ctx, fromRef)
	if err != nil {
		return err
	}
	toDigest, toRepo, err := s.Resolve(ctx, toRef)
	if err != nil {
		return err
	}
	if fromRepo != toRepo {
		return errors.New("copy-signature requires images in the same repository")
	}
	candidates, err := s.ListSignatures(ctx, fromRepo, fromDigest)
	if err != nil {
		return err
	}
	copied := 0
	for _, candidate := range candidates {
		if candidate.Foreign || len(candidate.Payload) == 0 || candidate.SigB64 == "" {
			continue
		}
		if err := s.PushSignature(ctx, toRepo, toDigest, candidate.Payload, candidate.SigB64, candidate.Algorithm); err != nil {
			return err
		}
		copied++
	}
	if copied == 0 {
		return errors.New("source image has no imgsign signature artifacts")
	}
	return nil
}
