package store

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/credentials"
)

type ORASStore struct {
	repoCache map[string]*remote.Repository
}

func NewORASStore() *ORASStore { return &ORASStore{repoCache: make(map[string]*remote.Repository)} }

func (s *ORASStore) repository(ref string) (*remote.Repository, registry.Reference, error) {
	parsed, err := registry.ParseReference(ref)
	if err != nil {
		return nil, parsed, err
	}
	name := parsed.Registry + "/" + parsed.Repository
	if r := s.repoCache[name]; r != nil {
		return r, parsed, nil
	}
	r, err := remote.NewRepository(name)
	if err != nil {
		return nil, parsed, err
	}
	if user, token := os.Getenv("GHCR_USER"), os.Getenv("GHCR_TOKEN"); user != "" && token != "" {
		r.Client = &auth.Client{Client: http.DefaultClient, Credential: auth.StaticCredential(parsed.Registry, auth.Credential{Username: user, Password: token})}
	} else if dockerStore, err := credentials.NewStoreFromDocker(credentials.StoreOptions{}); err == nil {
		r.Client = &auth.Client{Client: http.DefaultClient, Credential: credentials.Credential(dockerStore)}
	}
	s.repoCache[name] = r
	return r, parsed, nil
}

func (s *ORASStore) Resolve(ctx context.Context, ref string) (string, string, error) {
	r, parsed, err := s.repository(ref)
	if err != nil {
		return "", "", err
	}
	desc, err := r.Resolve(ctx, parsed.Reference)
	if err != nil {
		return "", "", fmt.Errorf("resolve image: %w", err)
	}
	return desc.Digest.String(), strings.ToLower(parsed.Registry + "/" + parsed.Repository), nil
}

func (s *ORASStore) PushSignature(ctx context.Context, repoName, subjectDigest string, raw []byte, sigB64 string) error {
	r, _, err := s.repository(repoName)
	if err != nil {
		return err
	}
	payloadDesc := ocispec.Descriptor{MediaType: PayloadMediaType, Digest: digest.FromBytes(raw), Size: int64(len(raw)), Annotations: map[string]string{SignatureAnnotation: sigB64}}
	if err := r.Push(ctx, payloadDesc, bytes.NewReader(raw)); err != nil {
		return fmt.Errorf("push payload: %w", err)
	}
	empty := []byte("{}")
	configDesc := ocispec.Descriptor{MediaType: "application/vnd.oci.empty.v1+json", Digest: digest.FromBytes(empty), Size: int64(len(empty))}
	if err := r.Push(ctx, configDesc, bytes.NewReader(empty)); err != nil {
		return fmt.Errorf("push config: %w", err)
	}
	subject := ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest, Digest: digest.Digest(subjectDigest)}
	manifest := ocispec.Manifest{Versioned: specs.Versioned{SchemaVersion: 2}, Config: configDesc, Layers: []ocispec.Descriptor{payloadDesc}, Subject: &subject, ArtifactType: SignatureArtifactType}
	data, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	manifestDesc := ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest, Digest: digest.FromBytes(data), Size: int64(len(data)), ArtifactType: SignatureArtifactType, Annotations: map[string]string{"org.opencontainers.image.created": "imgsign"}}
	if err := r.PushReference(ctx, manifestDesc, bytes.NewReader(data), manifestDesc.Digest.String()); err != nil {
		return fmt.Errorf("push signature manifest: %w", err)
	}
	return nil
}

func (s *ORASStore) ListSignatures(ctx context.Context, repoName, subjectDigest string) ([]Candidate, error) {
	r, _, err := s.repository(repoName)
	if err != nil {
		return nil, err
	}
	subject := ocispec.Descriptor{Digest: digest.Digest(subjectDigest)}
	var descriptors []ocispec.Descriptor
	if err := r.Referrers(ctx, subject, "", func(ds []ocispec.Descriptor) error { descriptors = append(descriptors, ds...); return nil }); err != nil {
		return nil, fmt.Errorf("list referrers: %w", err)
	}
	result := make([]Candidate, 0, len(descriptors))
	for _, desc := range descriptors {
		reader, err := r.Fetch(ctx, desc)
		if err != nil {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(reader, 1024*1024))
		reader.Close()
		if err != nil {
			continue
		}
		var manifest ocispec.Manifest
		if json.Unmarshal(data, &manifest) != nil {
			continue
		}
		if manifest.ArtifactType != SignatureArtifactType {
			result = append(result, Candidate{Foreign: true})
			continue
		}
		if len(manifest.Layers) == 0 {
			result = append(result, Candidate{})
			continue
		}
		layer := manifest.Layers[0]
		if layer.MediaType != PayloadMediaType {
			result = append(result, Candidate{})
			continue
		}
		layerReader, err := r.Fetch(ctx, layer)
		if err != nil {
			result = append(result, Candidate{})
			continue
		}
		payload, err := io.ReadAll(io.LimitReader(layerReader, 4097))
		layerReader.Close()
		if err != nil {
			continue
		}
		result = append(result, Candidate{Payload: payload, SigB64: layer.Annotations[SignatureAnnotation]})
	}
	return result, nil
}
