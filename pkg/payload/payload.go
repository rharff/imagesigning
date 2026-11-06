package payload

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const Domain = "imgsign.v1\n"

type Payload struct {
	Version   int    `json:"v"`
	Algorithm string `json:"alg"`
	Repo      string `json:"repo"`
	Digest    string `json:"digest"`
	IAT       int64  `json:"iat"`
}

func New(repo, digest string, iat int64, algorithm ...string) (Payload, error) {
	repo = strings.ToLower(strings.TrimSpace(repo))
	if repo == "" || digest == "" {
		return Payload{}, errors.New("repo and digest are required")
	}
	if strings.Contains(repo, "@") || strings.Contains(repo, ":") {
		return Payload{}, errors.New("repo must not contain tag or digest")
	}
	alg := "ecdsa"
	if len(algorithm) > 0 && algorithm[0] != "" {
		alg = algorithm[0]
	}
	return Payload{Version: 2, Algorithm: alg, Repo: repo, Digest: digest, IAT: iat}, nil
}

func (p Payload) Marshal() ([]byte, error) {
	if (p.Version != 1 && p.Version != 2) || p.Repo == "" || p.Digest == "" {
		return nil, errors.New("invalid payload")
	}
	return json.Marshal(struct {
		V      int    `json:"v"`
		Alg    string `json:"alg,omitempty"`
		Repo   string `json:"repo"`
		Digest string `json:"digest"`
		IAT    int64  `json:"iat"`
	}{p.Version, p.Algorithm, p.Repo, p.Digest, p.IAT})
}

func Parse(data []byte) (Payload, error) {
	var p Payload
	if err := json.Unmarshal(data, &p); err != nil {
		return p, fmt.Errorf("parse payload: %w", err)
	}
	if (p.Version != 1 && p.Version != 2) || p.Repo == "" || p.Digest == "" {
		return p, errors.New("invalid payload fields")
	}
	if p.Version == 1 {
		p.Algorithm = "ecdsa"
	}
	return p, nil
}

func SigningBytes(raw []byte) []byte { return bytes.Join([][]byte{[]byte(Domain), raw}, nil) }
