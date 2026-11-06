package unit_test

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"imgsign/pkg/keys"
	"imgsign/pkg/payload"
	"imgsign/pkg/signer"
	"imgsign/pkg/store"
	"imgsign/pkg/verifier"
)

type memoryStore struct {
	digest     string
	repo       string
	candidates []store.Candidate
}

func (m *memoryStore) Resolve(context.Context, string) (string, string, error) {
	return m.digest, m.repo, nil
}
func (m *memoryStore) PushSignature(_ context.Context, repo, digest string, raw []byte, sig, algorithm string) error {
	m.candidates = append(m.candidates, store.Candidate{Payload: raw, SigB64: sig, Algorithm: algorithm})
	return nil
}
func (m *memoryStore) ListSignatures(context.Context, string, string) ([]store.Candidate, error) {
	return m.candidates, nil
}

func TestSignAndVerify(t *testing.T) {
	key, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	s := &memoryStore{digest: "sha256:" + "a" + repeat("0", 63), repo: "ghcr.io/acme/app"}
	if _, err := signer.Sign(context.Background(), s, key, keys.ECDSA, "ghcr.io/acme/app:latest", time.Unix(1730000000, 0)); err != nil {
		t.Fatal(err)
	}
	if err := verifier.Verify(context.Background(), s, key.PublicKey(), keys.ECDSA, "ghcr.io/acme/app:latest"); err != nil {
		t.Fatal(err)
	}
}

func TestMLDSA65SignAndVerify(t *testing.T) {
	key, err := keys.GenerateAlgorithm(keys.MLDSA65)
	if err != nil {
		t.Fatal(err)
	}
	s := &memoryStore{digest: "sha256:" + repeat("1", 64), repo: "ghcr.io/acme/app"}
	if _, err := signer.Sign(context.Background(), s, key, keys.MLDSA65, "ref", time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	if err := verifier.Verify(context.Background(), s, key.PublicKey(), keys.MLDSA65, "ref"); err != nil {
		t.Fatal(err)
	}
}

func TestSigningRejectsAlgorithmMismatch(t *testing.T) {
	key, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	s := &memoryStore{digest: "sha256:" + repeat("2", 64), repo: "ghcr.io/acme/app"}
	if _, err := signer.Sign(context.Background(), s, key, keys.MLDSA65, "ref", time.Unix(1, 0)); err == nil ||
		err.Error() != "algorithm mismatch: private key is ecdsa, but signing requested mldsa65" {
		t.Fatalf("unexpected mismatch error: %v", err)
	}
}

func TestVerifierRejectsDifferentSignatureAlgorithm(t *testing.T) {
	key, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	s := &memoryStore{digest: "sha256:" + repeat("3", 64), repo: "ghcr.io/acme/app"}
	if _, err := signer.Sign(context.Background(), s, key, keys.ECDSA, "ref", time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	mldsaKey, err := keys.GenerateAlgorithm(keys.MLDSA65)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.Verify(context.Background(), s, mldsaKey.PublicKey(), keys.MLDSA65, "ref"); verifier.Code(err) != verifier.AlgorithmMismatch {
		t.Fatalf("different signature algorithm: got %v", err)
	}
}

func TestVerifierRejectsWrongKeyAndTamperedPayload(t *testing.T) {
	key, _ := keys.Generate()
	other, _ := keys.Generate()
	s := &memoryStore{digest: "sha256:" + repeat("b", 64), repo: "ghcr.io/acme/app"}
	if _, err := signer.Sign(context.Background(), s, key, keys.ECDSA, "ref", time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	if err := verifier.Verify(context.Background(), s, other.PublicKey(), keys.ECDSA, "ref"); verifier.Code(err) != verifier.BadSignature {
		t.Fatalf("wrong key: got %v", err)
	}
	s.candidates[0].Payload[0] = '['
	if err := verifier.Verify(context.Background(), s, key.PublicKey(), keys.ECDSA, "ref"); verifier.Code(err) != verifier.BadSignature {
		t.Fatalf("tampered payload: got %v", err)
	}
}

func TestVerifierRejectsDigestAndRepoMismatch(t *testing.T) {
	key, _ := keys.Generate()
	digest := "sha256:" + repeat("c", 64)
	s := &memoryStore{digest: digest, repo: "ghcr.io/acme/app"}
	p, _ := payload.New(s.repo, "sha256:"+repeat("d", 64), 1, keys.ECDSA)
	raw, _ := p.Marshal()
	s.candidates = []store.Candidate{{Payload: raw, SigB64: signPayload(t, key, raw)}}
	if err := verifier.Verify(context.Background(), s, key.PublicKey(), keys.ECDSA, "ref"); verifier.Code(err) != verifier.DigestMismatch {
		t.Fatalf("digest mismatch: got %v", err)
	}

	p, _ = payload.New("ghcr.io/acme/other", digest, 1, keys.ECDSA)
	raw, _ = p.Marshal()
	s.candidates = []store.Candidate{{Payload: raw, SigB64: signPayload(t, key, raw)}}
	if err := verifier.Verify(context.Background(), s, key.PublicKey(), keys.ECDSA, "ref"); verifier.Code(err) != verifier.RepoMismatch {
		t.Fatalf("repo mismatch: got %v", err)
	}
}

func TestVerifierRejectsForeignSignatureFormatAsUnsupported(t *testing.T) {
	key, _ := keys.Generate()
	s := &memoryStore{
		digest:     "sha256:" + repeat("f", 64),
		repo:       "ghcr.io/acme/app",
		candidates: []store.Candidate{{Foreign: true}},
	}
	if err := verifier.Verify(context.Background(), s, key.PublicKey(), keys.ECDSA, "ref"); verifier.Code(err) != verifier.UnsupportedSignature {
		t.Fatalf("foreign signature: got %v", err)
	}
}

func TestPayloadSerializationIsDeterministic(t *testing.T) {
	p, err := payload.New("GHCR.IO/Acme/App", "sha256:"+repeat("e", 64), 1730000000)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := p.Marshal()
	b, _ := p.Marshal()
	if string(a) != `{"v":2,"alg":"ecdsa","repo":"ghcr.io/acme/app","digest":"sha256:`+repeat("e", 64)+`","iat":1730000000}` || string(a) != string(b) {
		t.Fatalf("unexpected nondeterministic payload: %s", a)
	}
}

func signPayload(t *testing.T, key keys.PrivateKey, raw []byte) string {
	t.Helper()
	sig, err := key.Sign(payload.SigningBytes(raw))
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(sig)
}

func repeat(s string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += s
	}
	return out
}
