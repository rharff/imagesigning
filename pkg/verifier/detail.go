package verifier

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"imgsign/pkg/keys"
	"imgsign/pkg/payload"
	"imgsign/pkg/store"
)

type DetailReport struct {
	Valid      bool               `json:"valid"`
	Code       string             `json:"code,omitempty"`
	Algorithm  string             `json:"algorithm"`
	Repository string             `json:"repository"`
	Digest     string             `json:"digest"`
	Key        KeyMetrics         `json:"key"`
	PrivateKey *FileMetrics       `json:"private_key,omitempty"`
	Candidates []CandidateMetrics `json:"candidates"`
	Timing     TimingMetrics      `json:"timing"`
}

type KeyMetrics struct {
	Algorithm string `json:"algorithm"`
	FileBytes int64  `json:"file_bytes"`
}

type FileMetrics struct {
	Path  string `json:"path"`
	Bytes int64  `json:"bytes"`
}

type CandidateMetrics struct {
	Index                int    `json:"index"`
	Foreign              bool   `json:"foreign"`
	Algorithm            string `json:"algorithm,omitempty"`
	PayloadJSONBytes     int    `json:"payload_json_bytes"`
	SigningBytes         int    `json:"signing_bytes"`
	SignatureRawBytes    int    `json:"signature_raw_bytes"`
	SignatureBase64Bytes int    `json:"signature_base64_bytes"`
	ManifestBytes        int64  `json:"manifest_bytes"`
	ConfigBytes          int64  `json:"config_bytes"`
	LayerBytes           int64  `json:"layer_bytes"`
	SignatureValid       bool   `json:"signature_valid"`
}

type TimingMetrics struct {
	ResolveMilliseconds      int64 `json:"resolve_ms"`
	ListMilliseconds         int64 `json:"list_ms"`
	VerificationMilliseconds int64 `json:"verification_ms"`
	TotalMilliseconds        int64 `json:"total_ms"`
}

func VerifyDetail(ctx context.Context, s store.Store, key keys.PublicKey, algorithm, ref string, pubPath, privPath string) (DetailReport, error) {
	start := time.Now()
	report := DetailReport{Algorithm: algorithm, Candidates: []CandidateMetrics{}}
	if key == nil {
		return report, errors.New("public key is required")
	}
	if key.Algorithm() != algorithm {
		return report, fmt.Errorf("algorithm mismatch: public key is %s, but verification requested %s", key.Algorithm(), algorithm)
	}
	pubInfo, err := os.Stat(pubPath)
	if err != nil {
		return report, err
	}
	report.Key = KeyMetrics{Algorithm: key.Algorithm(), FileBytes: pubInfo.Size()}
	if privPath != "" {
		info, err := os.Stat(privPath)
		if err != nil {
			return report, err
		}
		report.PrivateKey = &FileMetrics{Path: privPath, Bytes: info.Size()}
	}

	t := time.Now()
	digest, repo, err := s.Resolve(ctx, ref)
	report.Timing.ResolveMilliseconds = time.Since(t).Milliseconds()
	if err != nil {
		return report, err
	}
	report.Repository, report.Digest = repo, digest

	t = time.Now()
	candidates, err := s.ListSignatures(ctx, repo, digest)
	report.Timing.ListMilliseconds = time.Since(t).Milliseconds()
	if err != nil {
		return report, err
	}
	for i, candidate := range candidates {
		rawSig, decodeErr := base64.StdEncoding.DecodeString(candidate.SigB64)
		metric := CandidateMetrics{
			Index: i, Foreign: candidate.Foreign, Algorithm: candidate.Algorithm,
			PayloadJSONBytes: len(candidate.Payload), SigningBytes: len(payload.SigningBytes(candidate.Payload)),
			SignatureRawBytes: len(rawSig), SignatureBase64Bytes: len(candidate.SigB64),
			ManifestBytes: candidate.ManifestBytes, ConfigBytes: candidate.ConfigBytes, LayerBytes: candidate.LayerBytes,
		}
		if decodeErr == nil && !candidate.Foreign && (candidate.Algorithm == "" || candidate.Algorithm == algorithm) {
			metric.SignatureValid = key.Verify(payload.SigningBytes(candidate.Payload), rawSig)
		}
		report.Candidates = append(report.Candidates, metric)
	}

	t = time.Now()
	verifyErr := VerifyCandidates(key, algorithm, repo, digest, candidates)
	report.Timing.VerificationMilliseconds = time.Since(t).Milliseconds()
	report.Timing.TotalMilliseconds = time.Since(start).Milliseconds()
	if verifyErr != nil {
		report.Code = Code(verifyErr)
		return report, verifyErr
	}
	report.Valid = true
	return report, nil
}

func VerifyCandidates(key keys.PublicKey, algorithm, repo, digest string, candidates []store.Candidate) error {
	if len(candidates) == 0 {
		return &Rejection{NoSignature}
	}
	hasCandidate, hasAlgorithmMismatch := false, false
	for _, c := range candidates {
		if c.Foreign {
			continue
		}
		hasCandidate = true
		if len(c.Payload) > 4096 {
			continue
		}
		sig, err := base64.StdEncoding.DecodeString(c.SigB64)
		if err != nil {
			continue
		}
		if c.Algorithm != "" && c.Algorithm != algorithm {
			hasAlgorithmMismatch = true
			continue
		}
		if !key.Verify(payload.SigningBytes(c.Payload), sig) {
			continue
		}
		p, err := payload.Parse(c.Payload)
		if err != nil {
			return &Rejection{BadSignature}
		}
		if p.Algorithm != algorithm {
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
	if !hasCandidate {
		return &Rejection{UnsupportedSignature}
	}
	if hasAlgorithmMismatch {
		return &Rejection{AlgorithmMismatch}
	}
	return &Rejection{BadSignature}
}

func (r DetailReport) JSON() ([]byte, error) { return json.MarshalIndent(r, "", "  ") }
