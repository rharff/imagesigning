package store

import "context"

const SignatureArtifactType = "application/vnd.imgsign.signature.v1"
const PayloadMediaType = "application/vnd.imgsign.payload.v1+json"
const SignatureAnnotation = "io.imgsign.signature"
const AlgorithmAnnotation = "io.imgsign.algorithm"

type Store interface {
	Resolve(context.Context, string) (digest string, repo string, err error)
	PushSignature(context.Context, string, string, []byte, string, string) error
	ListSignatures(context.Context, string, string) ([]Candidate, error)
}

type Candidate struct {
	Payload              []byte
	SigB64               string
	Algorithm            string
	ManifestBytes        int64
	ConfigBytes          int64
	LayerBytes           int64
	SignatureRawBytes    int
	SignatureBase64Bytes int
	// Foreign marks a referrer that is not an imgsign signature format.
	Foreign bool
}
