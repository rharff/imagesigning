package unit_test

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"imgsign/pkg/experiment"
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

type copyStore struct {
	resolved map[string]struct {
		digest string
		repo   string
	}
	candidates map[string][]store.Candidate
	pushed     []pushedSignature
}

type pushedSignature struct {
	repo    string
	digest  string
	payload []byte
	sig     string
	alg     string
}

func (m *copyStore) Resolve(_ context.Context, ref string) (string, string, error) {
	v := m.resolved[ref]
	return v.digest, v.repo, nil
}
func (m *copyStore) PushSignature(_ context.Context, repo, digest string, raw []byte, sig, algorithm string) error {
	m.pushed = append(m.pushed, pushedSignature{repo: repo, digest: digest, payload: append([]byte(nil), raw...), sig: sig, alg: algorithm})
	return nil
}
func (m *copyStore) ListSignatures(_ context.Context, repo, digest string) ([]store.Candidate, error) {
	return m.candidates[digest], nil
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

func TestCopySignatureCreatesDigestMismatchOnDestination(t *testing.T) {
	key, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	sourceDigest := "sha256:" + repeat("1", 64)
	destDigest := "sha256:" + repeat("2", 64)
	repo := "ghcr.io/acme/app"
	p, err := payload.New(repo, sourceDigest, 1730000000, keys.ECDSA)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := p.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	sig := signPayload(t, key, raw)
	s := &copyStore{
		resolved: map[string]struct {
			digest string
			repo   string
		}{
			"source:tag": {digest: sourceDigest, repo: repo},
			"dest:tag":   {digest: destDigest, repo: repo},
		},
		candidates: map[string][]store.Candidate{
			sourceDigest: {{Payload: raw, SigB64: sig, Algorithm: keys.ECDSA}},
		},
	}

	if err := experiment.CopySignature(context.Background(), s, "source:tag", "dest:tag"); err != nil {
		t.Fatal(err)
	}
	if len(s.pushed) != 1 || s.pushed[0].digest != destDigest {
		t.Fatalf("unexpected copied signatures: %+v", s.pushed)
	}

	s.candidates[destDigest] = []store.Candidate{{Payload: s.pushed[0].payload, SigB64: s.pushed[0].sig, Algorithm: keys.ECDSA}}
	// Copying a source payload to B must make verification reject the digest.
	verifyStore := &memoryStore{digest: destDigest, repo: repo, candidates: s.candidates[destDigest]}
	if err := verifier.Verify(context.Background(), verifyStore, key.PublicKey(), keys.ECDSA, "dest:tag"); verifier.Code(err) != verifier.DigestMismatch {
		t.Fatalf("copied signature verification: got %v, want digest_mismatch", err)
	}
}

func TestVerifyDetailArtifactByteFields(t *testing.T) {
	key, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := keys.SavePair(dir, key); err != nil {
		t.Fatal(err)
	}
	s := &memoryStore{
		digest: "sha256:" + repeat("3", 64),
		repo:   "ghcr.io/acme/app",
		candidates: []store.Candidate{{
			Payload:       []byte(`{"v":2,"alg":"ecdsa","repo":"ghcr.io/acme/app","digest":"sha256:` + repeat("3", 64) + `","iat":1}`),
			SigB64:        "AA==",
			Algorithm:     keys.ECDSA,
			ManifestBytes: 10,
			ConfigBytes:   20,
			LayerBytes:    30,
			IndexBytes:    40,
		}},
	}
	report, _ := verifier.VerifyDetail(context.Background(), s, key.PublicKey(), keys.ECDSA, "ref", dir+"/pub.pem", "")
	if len(report.Candidates) != 1 {
		t.Fatalf("got %d candidates", len(report.Candidates))
	}
	c := report.Candidates[0]
	if c.IndexBytes != 40 || c.TotalArtifactBytes != 100 {
		t.Fatalf("unexpected artifact bytes: index=%d total=%d", c.IndexBytes, c.TotalArtifactBytes)
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
