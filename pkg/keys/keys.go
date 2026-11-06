package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

const (
	ECDSA   = "ecdsa"
	MLDSA65 = "mldsa65"
)

type PrivateKey interface {
	Algorithm() string
	Sign([]byte) ([]byte, error)
	PublicKey() PublicKey
}

type PublicKey interface {
	Algorithm() string
	Verify([]byte, []byte) bool
}

type ecdsaPrivate struct{ *ecdsa.PrivateKey }
type ecdsaPublic struct{ *ecdsa.PublicKey }
type mldsaPrivate struct{ *mldsa65.PrivateKey }
type mldsaPublic struct{ *mldsa65.PublicKey }

func (k *ecdsaPrivate) Algorithm() string { return ECDSA }
func (k *ecdsaPrivate) Sign(data []byte) ([]byte, error) {
	sum := sha256.Sum256(data)
	return ecdsa.SignASN1(rand.Reader, k.PrivateKey, sum[:])
}
func (k *ecdsaPrivate) PublicKey() PublicKey { return &ecdsaPublic{&k.PrivateKey.PublicKey} }
func (k *ecdsaPublic) Algorithm() string     { return ECDSA }
func (k *ecdsaPublic) Verify(data, sig []byte) bool {
	sum := sha256.Sum256(data)
	return ecdsa.VerifyASN1(k.PublicKey, sum[:], sig)
}
func (k *mldsaPrivate) Algorithm() string { return MLDSA65 }
func (k *mldsaPrivate) Sign(data []byte) ([]byte, error) {
	sig := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(k.PrivateKey, data, nil, false, sig); err != nil {
		return nil, err
	}
	return sig, nil
}
func (k *mldsaPrivate) PublicKey() PublicKey {
	return &mldsaPublic{k.PrivateKey.Public().(*mldsa65.PublicKey)}
}
func (k *mldsaPublic) Algorithm() string { return MLDSA65 }
func (k *mldsaPublic) Verify(data, sig []byte) bool {
	return mldsa65.Verify(k.PublicKey, data, nil, sig)
}

func Generate() (PrivateKey, error) { return GenerateAlgorithm(ECDSA) }

func GenerateAlgorithm(algorithm string) (PrivateKey, error) {
	switch algorithm {
	case ECDSA:
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		return &ecdsaPrivate{key}, nil
	case MLDSA65:
		public, private, err := mldsa65.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		_ = public
		return &mldsaPrivate{private}, nil
	default:
		return nil, fmt.Errorf("unsupported algorithm %q (must be %s or %s)", algorithm, ECDSA, MLDSA65)
	}
}

func GenerateECDSA() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func SavePair(dir string, privateKey PrivateKey) error {
	privateBytes, publicBytes, privateType, publicType, err := marshalPair(privateKey)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if err := writeNew(filepath(dir, "priv.pem"), privateType, privateBytes, 0600); err != nil {
		return err
	}
	if err := writeNew(filepath(dir, "pub.pem"), publicType, publicBytes, 0644); err != nil {
		return err
	}
	return nil
}

func LoadPrivate(path string) (PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}
	return ParsePrivate(data)
}

func ParsePrivate(data []byte) (PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("private key is not PEM")
	}
	switch block.Type {
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse private key: %w", err)
		}
		ecdsaKey, ok := key.(*ecdsa.PrivateKey)
		if !ok || ecdsaKey.Curve != elliptic.P256() {
			return nil, errors.New("private key must be ECDSA P-256")
		}
		return &ecdsaPrivate{ecdsaKey}, nil
	case "ML-DSA-65 PRIVATE KEY":
		key := &mldsa65.PrivateKey{}
		if err := key.UnmarshalBinary(block.Bytes); err != nil {
			return nil, fmt.Errorf("parse ML-DSA-65 private key: %w", err)
		}
		return &mldsaPrivate{key}, nil
	default:
		return nil, fmt.Errorf("unsupported private key PEM type %q", block.Type)
	}
}

func LoadPublic(path string) (PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read public key: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("public key is not PEM")
	}
	switch block.Type {
	case "PUBLIC KEY":
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse public key: %w", err)
		}
		ecdsaKey, ok := key.(*ecdsa.PublicKey)
		if !ok || ecdsaKey.Curve != elliptic.P256() {
			return nil, errors.New("public key must be ECDSA P-256")
		}
		return &ecdsaPublic{ecdsaKey}, nil
	case "ML-DSA-65 PUBLIC KEY":
		key := &mldsa65.PublicKey{}
		if err := key.UnmarshalBinary(block.Bytes); err != nil {
			return nil, fmt.Errorf("parse ML-DSA-65 public key: %w", err)
		}
		return &mldsaPublic{key}, nil
	default:
		return nil, fmt.Errorf("unsupported public key PEM type %q", block.Type)
	}
}

func marshalPair(privateKey PrivateKey) ([]byte, []byte, string, string, error) {
	switch key := privateKey.(type) {
	case *ecdsaPrivate:
		priv, err := x509.MarshalPKCS8PrivateKey(key.PrivateKey)
		if err != nil {
			return nil, nil, "", "", fmt.Errorf("marshal private key: %w", err)
		}
		pub, err := x509.MarshalPKIXPublicKey(&key.PrivateKey.PublicKey)
		if err != nil {
			return nil, nil, "", "", fmt.Errorf("marshal public key: %w", err)
		}
		return priv, pub, "PRIVATE KEY", "PUBLIC KEY", nil
	case *mldsaPrivate:
		return key.Bytes(), key.PrivateKey.Public().(*mldsa65.PublicKey).Bytes(), "ML-DSA-65 PRIVATE KEY", "ML-DSA-65 PUBLIC KEY", nil
	default:
		return nil, nil, "", "", errors.New("unsupported private key type")
	}
}

func writeNew(path, kind string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: kind, Bytes: data}); err != nil {
		return err
	}
	return nil
}

func filepath(dir, name string) string { return dir + string(os.PathSeparator) + name }
