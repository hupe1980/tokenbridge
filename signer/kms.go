package signer

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/golang-jwt/jwt/v5"
	"github.com/hupe1980/tokenbridge"
	"github.com/hupe1980/tokenbridge/keyset"
)

// KMSClient defines the methods that are needed from AWS KMS client for signing tokens and fetching public keys.
type KMSClient interface {
	// Sign signs a digest with the given key using KMS.
	Sign(ctx context.Context, input *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error)
	// GetPublicKey retrieves the public key associated with the given key ID.
	GetPublicKey(ctx context.Context, input *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
}

// KMS represents a signer that uses AWS Key Management Service (KMS) to sign JWT tokens.
type KMS struct {
	kmsClient KMSClient                  // AWS KMS client
	keyID     string                     // The ID of the KMS key used for signing
	alg       types.SigningAlgorithmSpec // The signing algorithm to use
}

// NewKMS creates a new instance of KMS with the given client, key ID, and signing algorithm.
func NewKMS(kmsClient KMSClient, keyID string, alg types.SigningAlgorithmSpec) tokenbridge.Signer {
	return &KMS{
		kmsClient: kmsClient,
		keyID:     keyID,
		alg:       alg,
	}
}

// SignToken signs a JWT token using the KMS service. It serializes the token, computes the hash, and then signs it using KMS.
//
// Parameters:
//   - ctx: The context to use for the signing request.
//   - token: The JWT token that needs to be signed.
//
// Returns:
//   - The signed JWT token as a string.
//   - An error if the signing process fails.
func (s *KMS) SignToken(ctx context.Context, token *jwt.Token) (string, error) {
	// Serialize the token into a string for signing
	tokenString, err := token.SigningString()
	if err != nil {
		return "", fmt.Errorf("failed to serialize token: %w", err)
	}

	// Compute the hash based on the selected signing algorithm
	var hash []byte

	switch s.alg { // nolint exhaustive
	case types.SigningAlgorithmSpecRsassaPkcs1V15Sha256, types.SigningAlgorithmSpecRsassaPssSha256, types.SigningAlgorithmSpecEcdsaSha256:
		h := sha256.Sum256([]byte(tokenString))
		hash = h[:]
	case types.SigningAlgorithmSpecRsassaPkcs1V15Sha384, types.SigningAlgorithmSpecRsassaPssSha384, types.SigningAlgorithmSpecEcdsaSha384:
		h := sha512.Sum384([]byte(tokenString))
		hash = h[:]
	case types.SigningAlgorithmSpecRsassaPkcs1V15Sha512, types.SigningAlgorithmSpecRsassaPssSha512, types.SigningAlgorithmSpecEcdsaSha512:
		h := sha512.Sum512([]byte(tokenString))
		hash = h[:]
	default:
		return "", fmt.Errorf("unsupported signing algorithm: %s", s.alg)
	}

	// Sign the hashed message using AWS KMS
	signInput := &kms.SignInput{
		KeyId:            aws.String(s.keyID),
		Message:          hash,
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: s.alg,
	}

	signOutput, err := s.kmsClient.Sign(ctx, signInput)
	if err != nil {
		return "", fmt.Errorf("failed to sign with KMS: %w", err)
	}

	// Combine the signed hash with the original token string and return it
	return fmt.Sprintf("%s.%s", tokenString, base64.RawURLEncoding.EncodeToString(signOutput.Signature)), nil
}

// GetJWKS retrieves the JSON Web Key Set (JWKS) containing the public key used for verifying the signed tokens.
//
// Parameters:
//   - ctx: The context to use for the public key retrieval request.
//
// Returns:
//   - A JWKS containing the public key(s) for verifying the token signature.
//   - An error if retrieving the public key or constructing the JWKS fails.
func (s *KMS) GetJWKS(ctx context.Context) (*keyset.JWKS, error) {
	// Map the KMS signing algorithm to the corresponding JWT signing method.
	signingMethod := getSigningMethod(s.alg)
	if signingMethod == nil {
		return nil, fmt.Errorf("unsupported signing algorithm: %s", s.alg)
	}

	// Retrieve the public key from AWS KMS
	getPubKeyInput := &kms.GetPublicKeyInput{
		KeyId: aws.String(s.keyID),
	}

	getPubKeyOutput, err := s.kmsClient.GetPublicKey(ctx, getPubKeyInput)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve public key from KMS: %w", err)
	}

	// Parse and construct the JWK from the retrieved public key
	var jwk keyset.JWK

	switch signingMethod {
	case jwt.SigningMethodRS256, jwt.SigningMethodRS384, jwt.SigningMethodRS512,
		jwt.SigningMethodPS256, jwt.SigningMethodPS384, jwt.SigningMethodPS512:
		// Parse RSA public key
		pubKey, err := jwt.ParseRSAPublicKeyFromPEM(getPubKeyOutput.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse RSA public key: %w", err)
		}

		// Construct the RSA JWK
		jwk = keyset.JWK{
			Kty: "RSA",                                                  // Key type
			Alg: signingMethod.Alg(),                                    // Algorithm used for signing
			Use: "sig",                                                  // Key usage (signature)
			Kid: s.keyID,                                                // Key ID
			N:   base64.RawURLEncoding.EncodeToString(pubKey.N.Bytes()), // RSA modulus
			E:   base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}),  // RSA exponent (default for RSA keys)
		}
	case jwt.SigningMethodES256, jwt.SigningMethodES384, jwt.SigningMethodES512:
		// Parse EC public key
		pubKey, err := jwt.ParseECPublicKeyFromPEM(getPubKeyOutput.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse EC public key: %w", err)
		}

		// Determine the curve name
		var crv string

		switch pubKey.Curve.Params().Name {
		case "P-256":
			crv = "P-256"
		case "P-384":
			crv = "P-384"
		case "P-521":
			crv = "P-521"
		default:
			return nil, fmt.Errorf("unsupported elliptic curve: %s", pubKey.Curve.Params().Name)
		}

		// Construct the EC JWK
		jwk = keyset.JWK{
			Kty: "EC",                                                   // Key type
			Alg: signingMethod.Alg(),                                    // Algorithm used for signing
			Use: "sig",                                                  // Key usage (signature)
			Kid: s.keyID,                                                // Key ID
			Crv: crv,                                                    // Curve name
			X:   base64.RawURLEncoding.EncodeToString(pubKey.X.Bytes()), // X coordinate
			Y:   base64.RawURLEncoding.EncodeToString(pubKey.Y.Bytes()), // Y coordinate
		}
	default:
		return nil, fmt.Errorf("unsupported signing method: %s", signingMethod.Alg())
	}

	return &keyset.JWKS{Keys: []keyset.JWK{jwk}}, nil
}

// SigningMethod returns the JWT signing method corresponding to the KMS signing algorithm.
func (s *KMS) SigningMethod() jwt.SigningMethod {
	return getSigningMethod(s.alg)
}

// KeyID returns the ID of the KMS key used for signing.
func (s *KMS) KeyID() string {
	return s.keyID
}

// getSigningMethod maps the AWS KMS signing algorithm to a corresponding JWT signing method.
func getSigningMethod(alg types.SigningAlgorithmSpec) jwt.SigningMethod {
	// Return the appropriate signing method based on the algorithm
	switch alg { // nolint exhaustive
	case types.SigningAlgorithmSpecRsassaPkcs1V15Sha256:
		return jwt.SigningMethodRS256
	case types.SigningAlgorithmSpecRsassaPkcs1V15Sha384:
		return jwt.SigningMethodRS384
	case types.SigningAlgorithmSpecRsassaPkcs1V15Sha512:
		return jwt.SigningMethodRS512
	case types.SigningAlgorithmSpecRsassaPssSha256:
		return jwt.SigningMethodPS256
	case types.SigningAlgorithmSpecRsassaPssSha384:
		return jwt.SigningMethodPS384
	case types.SigningAlgorithmSpecRsassaPssSha512:
		return jwt.SigningMethodPS512
	case types.SigningAlgorithmSpecEcdsaSha256:
		return jwt.SigningMethodES256
	case types.SigningAlgorithmSpecEcdsaSha384:
		return jwt.SigningMethodES384
	case types.SigningAlgorithmSpecEcdsaSha512:
		return jwt.SigningMethodES512
	default:
		return nil // Unsupported algorithm
	}
}
