package tokenbridge

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	// nolint gosec no real key
	privateRSAKeyString = `-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDNASlRgl1vfXRg
iphK5rC5IwH10YktWBX+d1DAGXbAC1OwFn0OKjHxpR/uQwcKDr19+z/xJuLm3hJ0
Vc7p9Cj+9nOz8yfTWq3+NyDfrudbkPfjR1Yz/T0PSTPS53EWslVioi5Vx+s2QS3Q
ksZzWImLRvPD5HJlUX407qn5EfyyEhBX1+Wn9JSM64lm0SXWPRkp72pY6ZZvd6t5
sb6Yu0ERE3OPZmwDwhaHA5822kozU0GpPDryALxxFVJx2ABdfhstpvpJqdHQOWAZ
bkechPbLAuA8yk/yusTDgVQqmiqzF5xaGrktPImllfYtuweMGlRxZgZliDmJ7zj9
hxHoeHXRAgMBAAECggEAMKQ754klHlUIDfgUloESIXt69ZaYE9g4r74jvNDN6ldF
rhxH49qDKzDg2Kmyu+Ivd/rrew6c++ZpPo01oTE7oPNdFK93HaEAc7ck564aWxGU
n6rHe2J04HGgCES+AoKh29tbXyMmXiMs+bY5vBif2holsK89rWiep3SRg/WOnbla
zI+yLDd+VK9TYphH1DseM4DvmHahL358S3NEecSHRL8O7BGP2z1Wb9hFctiXCVoO
kW6vVz+aTluJD3QtClrOhVHk7gzZ0cvF/WF1iTFhS92umQ6R9Mqq5lj1o0fTXf81
3XCRFl8k6yiyYi1edlg0X4RQ7yd9Njf8+kzmchNUOQKBgQDmBQGzs3wRqz1jaD2A
1qXsnO/G4Yrn6z/g38oxXnIcL7hFmgpn7h+lB/lo1lU2WARKxsIOTJqQcBedvNoe
H3kdy/Mw/HAn+Ngf1vthUgpgUJN3boPuDhOZO1xgGKN703wXpEDy71RAsnDEb+SK
ENBPJP+/WQv5RAdAd4uvT9EIlwKBgQDkKNkMMLKuvHJSFW7Tg7UH5NOZK5pywPBg
2AKeO8A4c0dt6knPIFDboV6+xXABv5EUyjkZjNIcXVnojJqi8x2BWN8MCy3gyMR1
8WTbpSRhHhguQEdSEPYQ4MAqwaIFAsvB4FFzrke3YPXBYi0CYDaERA7Ri2AX4Kv1
uEuDzXiZ1wKBgA7+ZI4CNSQxtV61fMzZMRerYzXjndpgS1mtPNDbBzUvJyPiVqtP
qmBnlKpwzj0sn5sAOcYU2D5yEBgIJ2+vPYXjtYaL7gOtBOmOafR+FI8SsYonehIa
eMyUQgFBmeaIcp5X5qPvVd6hwxgK8yrMzcda8hDXDSDCfnaFVGWpHkchAoGAUsUa
0FhOSiOlGXAbD3KFVwLFXJi75AtoaMmUUZD9j70KWa6X7iMcEkE9XNnFY2z6ld8y
zbkPdCjNeBah9qFZv9XcvMLFdvl+hAb5ftEvHGhNf2HkPbpXehH+xMQQId88ye21
vtCnxbfQD8Ks72K2BE+oTI5SYvcnivG7u2nr6WsCgYA3eCkc3UyGrT18/R8F57PQ
bQZuGVClsbeJkrcTtIMgCT+0KhBGYyCjvEahky0WcKlTCcLX1OMSknIA7YMCbWQ3
qDg/Thja4xMsBA957dbfdQSH5KzOwoLO+fSGjDuQN+7Xvr+NqFsWDwId1cLai694
5DAzavPOnl9Okefi6P9Ntg==
-----END PRIVATE KEY-----`
	expectedRSAThumbprint = "Dy6gufsOYqCgKLis6fedxHJkduSOBcV4x9zzOehUgh0"
)

var (
	// nolint gosec no real key
	privateECKeyString = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIP1/XfntwTG5/keyqKEP9xxVzitaRyjRpCoLmT/4xbN1oAoGCCqGSM49
AwEHoUQDQgAEPGHIk8Tk0KqxTNgfu5BRgy8rtDSvaBggbmj8Ps0wv7Kzn78VyRHL
tLCe5GXCI/EdZeZRw5Kv8VFMxBocMXq8AA==
-----END EC PRIVATE KEY-----`
	expectedECThumbprint = "ZSpLYiTtTyrcblwZyeZ9U3OvMK2Zo6TAO0827e1cI_E"
)

func loadRSAPrivateKey() (*rsa.PrivateKey, error) {
	return jwt.ParseRSAPrivateKeyFromPEM([]byte(privateRSAKeyString))
}

func loadRSAPublicKey() (*rsa.PublicKey, error) {
	privateKey, err := loadRSAPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to load private key: %w", err)
	}

	return &privateKey.PublicKey, nil
}

func loadECPrivateKey() (*ecdsa.PrivateKey, error) {
	return jwt.ParseECPrivateKeyFromPEM([]byte(privateECKeyString))
}

func loadECPublicKey() (*ecdsa.PublicKey, error) {
	privateKey, err := loadECPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to load EC private key: %w", err)
	}

	return &privateKey.PublicKey, nil
}

func createIDToken(privateKey *rsa.PrivateKey) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"sub": "1234567890",
		"iss": "http://fake-oidc.local", // must match issuer
		"aud": "my-local-app",           // must match client ID
		"exp": now.Add(time.Hour).Unix(),
		"iat": now.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "test-key" // must match the JWKS key

	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return signedToken, nil
}

func createECIDToken(privateKey *ecdsa.PrivateKey) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"sub": "1234567890",
		"iss": "http://fake-oidc.local", // must match issuer
		"aud": "my-local-app",           // must match client ID
		"exp": now.Add(time.Hour).Unix(),
		"iat": now.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = "ec-test-key" // must match the JWKS key

	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return signedToken, nil
}

type fakeRoundTripper struct{}

func (f *fakeRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	var data string

	switch {
	case strings.HasSuffix(req.URL.Path, "/.well-known/openid-configuration"):
		data = `{
			"issuer": "http://fake-oidc.local",
			"jwks_uri": "http://fake-oidc.local/keys"
		}`
	case strings.HasSuffix(req.URL.Path, "/keys"):
		rsaPublicKey, err := loadRSAPublicKey()
		if err != nil {
			return nil, fmt.Errorf("failed to load RSA public key: %w", err)
		}

		ecPublicKey, err := loadECPublicKey()
		if err != nil {
			return nil, fmt.Errorf("failed to load EC public key: %w", err)
		}

		data = `{
			"keys": [
				{
					"kty": "RSA",
					"alg": "RS256",
					"use": "sig",
					"kid": "test-key",
					"n": "` + base64.RawURLEncoding.EncodeToString(rsaPublicKey.N.Bytes()) + `",
					"e": "AQAB"
				},
				{
					"kty": "EC",
					"alg": "ES256",
					"use": "sig",
					"kid": "ec-test-key",
					"x": "` + base64.RawURLEncoding.EncodeToString(ecPublicKey.X.Bytes()) + `",
					"y": "` + base64.RawURLEncoding.EncodeToString(ecPublicKey.Y.Bytes()) + `",
					"crv": "P-256"
				}
			]
		}`
	default:
		return nil, fmt.Errorf("unexpected path: %s", req.URL.Path)
	}

	return &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader([]byte(data))),
	}, nil
}

func TestIDTokenVerification(t *testing.T) {
	t.Run("RSA Key Verification", func(t *testing.T) {
		t.Run("Valid RSA Key with Correct Thumbprint", func(t *testing.T) {
			privateKey, err := loadRSAPrivateKey()
			if err != nil {
				t.Fatalf("Failed to load RSA private key: %v", err)
			}

			token, err := createIDToken(privateKey)
			if err != nil {
				t.Fatalf("Failed to create RSA ID token: %v", err)
			}

			providerURL, err := url.Parse("http://fake-oidc.local")
			if err != nil {
				t.Fatalf("Failed to parse provider URL: %v", err)
			}

			ctx := context.Background()

			provider, err := NewOIDCVerifier(ctx, providerURL, []string{"my-local-app"}, func(o *OIDCVerifierOptions) {
				o.Transport = &fakeRoundTripper{}
				o.Thumbprints = []string{expectedRSAThumbprint}
			})
			if err != nil {
				t.Fatalf("Failed to create OIDC provider: %v", err)
			}

			if _, err := provider.Verify(ctx, token); err != nil {
				t.Fatalf("Failed to verify RSA ID token: %v", err)
			}
		})

		t.Run("Valid RSA Key with Incorrect Thumbprint", func(t *testing.T) {
			privateKey, err := loadRSAPrivateKey()
			if err != nil {
				t.Fatalf("Failed to load RSA private key: %v", err)
			}

			token, err := createIDToken(privateKey)
			if err != nil {
				t.Fatalf("Failed to create RSA ID token: %v", err)
			}

			providerURL, err := url.Parse("http://fake-oidc.local")
			if err != nil {
				t.Fatalf("Failed to parse provider URL: %v", err)
			}

			ctx := context.Background()

			provider, err := NewOIDCVerifier(ctx, providerURL, []string{"my-local-app"}, func(o *OIDCVerifierOptions) {
				o.Transport = &fakeRoundTripper{}
				o.Thumbprints = []string{"invalid-thumbprint"}
			})
			if err != nil {
				t.Fatalf("Failed to create OIDC provider: %v", err)
			}

			if _, err := provider.Verify(ctx, token); err == nil {
				t.Fatalf("Expected error for invalid RSA thumbprint, but got none")
			}
		})
	})

	t.Run("EC Key Verification", func(t *testing.T) {
		t.Run("Valid EC Key with Correct Thumbprint", func(t *testing.T) {
			privateKey, err := loadECPrivateKey()
			if err != nil {
				t.Fatalf("Failed to load EC private key: %v", err)
			}

			token, err := createECIDToken(privateKey)
			if err != nil {
				t.Fatalf("Failed to create EC ID token: %v", err)
			}

			providerURL, err := url.Parse("http://fake-oidc.local")
			if err != nil {
				t.Fatalf("Failed to parse provider URL: %v", err)
			}

			ctx := context.Background()

			provider, err := NewOIDCVerifier(ctx, providerURL, []string{"my-local-app"}, func(o *OIDCVerifierOptions) {
				o.Transport = &fakeRoundTripper{}
				o.SupportedSigningAlgs = []string{"ES256"}
				o.Thumbprints = []string{expectedECThumbprint}
			})
			if err != nil {
				t.Fatalf("Failed to create OIDC provider: %v", err)
			}

			if _, err := provider.Verify(ctx, token); err != nil {
				t.Fatalf("Failed to verify EC ID token: %v", err)
			}
		})

		t.Run("Valid EC Key with Incorrect Thumbprint", func(t *testing.T) {
			privateKey, err := loadECPrivateKey()
			if err != nil {
				t.Fatalf("Failed to load EC private key: %v", err)
			}

			token, err := createECIDToken(privateKey)
			if err != nil {
				t.Fatalf("Failed to create EC ID token: %v", err)
			}

			providerURL, err := url.Parse("http://fake-oidc.local")
			if err != nil {
				t.Fatalf("Failed to parse provider URL: %v", err)
			}

			ctx := context.Background()

			provider, err := NewOIDCVerifier(ctx, providerURL, []string{"my-local-app"}, func(o *OIDCVerifierOptions) {
				o.Transport = &fakeRoundTripper{}
				o.SupportedSigningAlgs = []string{"ES256"}
				o.Thumbprints = []string{"invalid-thumbprint"}
			})
			if err != nil {
				t.Fatalf("Failed to create OIDC provider: %v", err)
			}

			if _, err := provider.Verify(ctx, token); err == nil {
				t.Fatalf("Expected error for invalid EC thumbprint, but got none")
			}
		})
	})
}
