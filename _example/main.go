package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/hupe1980/tokenbridge"
)

func main() {
	ctx := context.Background()

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(privateRSAKeyString))
	if err != nil {
		log.Fatalf("Failed to parse private key: %v", err)
	}

	// Create an RSASigner
	rsaSigner := tokenbridge.NewRSA256Signer(privateKey, "rsa-key-id")

	issuerURL, err := url.Parse("https://token.actions.githubusercontent.com")
	if err != nil {
		log.Fatalf("Failed to parse issuer URL: %v", err)
	}

	oidcVerifier, err := tokenbridge.NewOIDCVerifier(ctx, issuerURL, []string{"my-local-app"})
	if err != nil {
		log.Fatalf("Failed to create OIDC verifier: %v", err)
	}

	issuer := tokenbridge.NewTokenIssuerWithJWKS("https://my-auth-server.org", rsaSigner)

	tokenBridge := tokenbridge.New(oidcVerifier)
	tokenBridge.SetDefaultIssuer(issuer)

	// Define the /exchange route
	http.HandleFunc("/exchange", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Parse the JSON payload
		var payload struct {
			IDToken string `json:"id_token"`
		}

		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, fmt.Sprintf("Invalid JSON payload: %v", err), http.StatusBadRequest)
			return
		}

		// Validate the ID token
		if payload.IDToken == "" {
			http.Error(w, "Missing id_token", http.StatusBadRequest)
			return
		}

		// Exchange the token
		accessToken, err := tokenBridge.ExchangeToken(r.Context(), payload.IDToken)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to exchange token: %v", err), http.StatusInternalServerError)
			return
		}

		// Return the access token
		w.Header().Set("Content-Type", "application/json")

		if err := json.NewEncoder(w).Encode(map[string]string{
			"access_token": accessToken,
		}); err != nil {
			http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
			return
		}
	})

	// Define the .well-known/jwks.json route
	http.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Get the JWKS
		jwks, err := issuer.GetJWKS(r.Context())
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to get JWKS: %v", err), http.StatusInternalServerError)
			return
		}

		// Return the JWKS
		w.Header().Set("Content-Type", "application/json")

		if err := json.NewEncoder(w).Encode(jwks); err != nil {
			http.Error(w, fmt.Sprintf("Failed to encode JWKS: %v", err), http.StatusInternalServerError)
			return
		}
	})

	// Start the HTTP server
	log.Println("Starting server on :8080")

	server := &http.Server{
		Addr:         ":8080",
		Handler:      nil,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  15 * time.Second,
	}

	log.Fatal(server.ListenAndServe())
}

// nolint gosec no real key
var privateRSAKeyString = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDTotPNB7f9T4zX
ejne1EbriUd/NVByfzwujyrfIRyRsF4Ui2V2eDa6h6oJjlTctFEZ/4OJPp9pG/TE
In7T6UbjDddqKSpMS5a/1Nxa002R6HerwUGf6AKmpQbpNXIaW61UikllxE811CnO
tIka/ix/aBmxobL881eioZFvSTkSt3RTJLyW1K2qr4uDRhKi+rxin+uLtu93AbPM
a3zuJSdSjeJge9ferZc3HtjzuQPBc21yNyFFwPtP0COyt16JNFIFjAtGZ/NPZeM0
2/At6nArPpn1ZMJRg0bAOFM7i796eQ89qnoBh8c2rAgzbW/29htpdeeZvHFL8ZvX
Aiil5kfnAgMBAAECggEAUSjNuYBexhU2KUIVpEbaxaO5F+btqWLyxNYhdjz/9Dzi
71T/vX1fW4wAILcFAzhhK6upmT27KzdN19N0uLZqeVNLC0qrDmQkdP9f27LRugUg
s2yiynxSW+7IZjGZRtNmdperiwvL5pQszji8pW3Yyak1xUGB3vBA6Ly2BavaZ7rh
Gh2fO1CQcnHL1/OIg0viXbGH1PEYaLg00MtBbr1P8obPkv0gnZHZpRiCiuAE6HEH
Rv1S50KE1fkz7t5relYNsqJC3xBJJFPhVUpxw8QWB2RyXf2z2r9D7YA+CGpMxgJg
AgMItcj/2mLeESs5na+s+rpBUtmbnNCrXTLjF+ZaLQKBgQDvAOa2LRJ/1t6f2+nP
cs4FUmmmFMUfezfyBsoENg5Lyaoph4LPFWXyABGGc+LV4av7JDW2e+TkoAbubp7+
bBfdTNSSC6UPdbvoXy/sK7bCALK0mh9oDctZje/Gfj80olOxoKaFOuaqkDbdPczc
kVj6qF4IPiCeRUICRCGvuskGjQKBgQDir7JZ07h5Yx2VJs8ezOXRm3dPDMlkCLfU
RRE3BPSe1oEcOCDkIT8jSwE+zk3Q7qgKcV2BQL8fq7n4gsLVuVLUG0g2L92hnqAo
q4OoeZVfE71/yY3eT7n/ZBn5T4FyVBpnxRtwEGzFCVDYT06Z1dxV5+eYaUOEXYtX
SNUHzMAVQwKBgQDaL/Nu+mS6CjmArK2dcYw89Yh3UtzGKaHgNGx2Pbb9XyQV95zm
Wf2QWJmnKeI6KWPsyJi0eBR01tadEqXZVGrQ35Pro+/S1kNuFn/UVe/o2eRK1ay4
PGeY4Oe1SImBDnPjY+rBFA2CRlef0AxWi+Y0JkJ5ueXjNwzUrsgl+hoM/QKBgAFs
0VY3OoWo1drGL68l4pv6ujlI/0sdsuomtQD/ivokpxMiVzKX8ump4wweB+c0WOIX
7FqPqaPtVHH3gHoPfDHRKhcNHfuSH7ehvGYmvYWnfh17iuTG44hzfKZQlaO+W5wj
ZRTDRavHbzas6PWWnpf7qT0QDFicre+SiaRO6TY5AoGAGSBqL5o+9lc0Mb8H9iIp
uyeZ1t9NyYWVSLRvxQBil5wFwEUDZvqYFENGCarG6gXzZUVYH+BY6lyaf46EC9mB
yeSPLrhr6wiGLFR+wqOLjlt2VxunaGiArCPKDp2EUDGXMZpkC9XpA5PB/dNbUod2
VuvyL+hYxKuPU3KejkOZKyc=
-----END PRIVATE KEY-----`
