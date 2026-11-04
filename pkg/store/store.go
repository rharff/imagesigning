package store

import "context"

const SignatureArtifactType = "application/vnd.imgsign.signature.v1"
const PayloadMediaType = "application/vnd.imgsign.payload.v1+json"
const SignatureAnnotation = "io.imgsign.signature"

type Store interface {
	Resolve(context.Context, string) (digest string, repo string, err error)
	PushSignature(context.Context, string, string, []byte, string) error
	ListSignatures(context.Context, string, string) ([]Candidate, error)
}

type Candidate struct {
	Payload []byte
	SigB64  string
	// Foreign marks a referrer that is not an imgsign signature format.
	Foreign bool
}
