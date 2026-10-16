package signer

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// KMSAPI is the slice of the KMS client the signer uses.
type KMSAPI interface {
	GetPublicKey(ctx context.Context, in *kms.GetPublicKeyInput, opts ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
	Sign(ctx context.Context, in *kms.SignInput, opts ...func(*kms.Options)) (*kms.SignOutput, error)
}

// KMS signs with an asymmetric ECC_NIST_P256 KMS key. The kid is the KMS key
// id (the UUID, not the ARN), so a JWKS consumer sees a stable opaque id.
type KMS struct {
	client KMSAPI
	keyID  string
	pub    *ecdsa.PublicKey
}

// NewKMS fetches the public key once at construction.
func NewKMS(ctx context.Context, client KMSAPI, keyID string) (*KMS, error) {
	out, err := client.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: &keyID})
	if err != nil {
		return nil, fmt.Errorf("signer: kms GetPublicKey %s: %w", keyID, err)
	}
	if out.KeySpec != types.KeySpecEccNistP256 {
		return nil, fmt.Errorf("signer: kms key %s is %s, want ECC_NIST_P256", keyID, out.KeySpec)
	}
	generic, err := x509.ParsePKIXPublicKey(out.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("signer: parse kms public key: %w", err)
	}
	pub, ok := generic.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("signer: kms key %s is not ECDSA", keyID)
	}
	kid := keyID
	if out.KeyId != nil {
		kid = shortKeyID(*out.KeyId)
	}
	return &KMS{client: client, keyID: kid, pub: pub}, nil
}

func (k *KMS) KeyID() string            { return k.keyID }
func (k *KMS) Public() *ecdsa.PublicKey { return k.pub }

func (k *KMS) Sign(ctx context.Context, digest []byte) ([]byte, error) {
	if len(digest) != 32 {
		return nil, fmt.Errorf("signer: digest must be 32 bytes, got %d", len(digest))
	}
	out, err := k.client.Sign(ctx, &kms.SignInput{
		KeyId:            &k.keyID,
		Message:          digest,
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: types.SigningAlgorithmSpecEcdsaSha256,
	})
	if err != nil {
		return nil, fmt.Errorf("signer: kms Sign: %w", err)
	}
	return DERToRaw(out.Signature)
}

// shortKeyID strips an ARN down to the trailing key UUID.
func shortKeyID(arn string) string {
	for i := len(arn) - 1; i >= 0; i-- {
		if arn[i] == '/' {
			return arn[i+1:]
		}
	}
	return arn
}
