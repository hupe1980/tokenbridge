# 🔐 TokenBridge
![Build Status](https://github.com/hupe1980/tokenbridge/workflows/Build/badge.svg) 
[![Go Reference](https://pkg.go.dev/badge/github.com/hupe1980/tokenbridge.svg)](https://pkg.go.dev/github.com/hupe1980/tokenbridge)
[![goreportcard](https://goreportcard.com/badge/github.com/hupe1980/tokenbridge)](https://goreportcard.com/report/github.com/hupe1980/tokenbridge)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**TokenBridge** is a lightweight and flexible Go library designed to bridge identity systems securely. It enables you to verify ID tokens, exchange them for signed access tokens, and serve JSON Web Key Sets (JWKS) for downstream token validation.

---

## ✨ Features

- ✅ **ID Token Verification**  
  Validate OIDC-issued ID tokens using flexible verification options.
  
- 🔁 **Token Exchange**  
  Transform ID tokens into signed access tokens with optional custom claims.
  
- 🔑 **JWKS Generation**  
  Serve JSON Web Key Sets to allow downstream systems to verify your tokens.

- 🌐 **Flexible Routing**  
  Route token exchanges based on ID token claims using regex-based matching.

---

## 🧭 Architecture

Here's how TokenBridge works in a typical token exchange flow:

```plaintext
+-------------------+       +-------------------+       +-------------------+
|                   |       |                   |       |                   |
|      Client       |       |   TokenBridge     |       |   OIDC Provider   |
|                   |       |                   |       |                   |
+-------------------+       +-------------------+       +-------------------+
          |                           |                           |
          |   1. Sends ID Token       |                           |
          +-------------------------->|                           |
          |                           |                           |
          |                           |   2. Verifies ID Token    |
          |                           +-------------------------->|
          |                           |                           |
          |   3. Returns Access Token |                           |
          +<--------------------------+                           |
          |                           |                           |

```    
## 🧩 Components

### 👤 Client
- Sends an ID token to TokenBridge for verification.
- Receives a newly issued access token.

### 🔐 TokenBridge
- Verifies ID tokens using an OIDC provider.
- Issues signed access tokens with support for custom claims.
- Serves a JWKS endpoint for public key distribution.
- Routes token exchanges based on ID Token claims.

### 🪪 OIDC Provider
- Issues standards-compliant ID tokens.
- Works with any OIDC-compatible identity provider (e.g., Auth0, Google, Okta).

## 🚀 Related Projects

Looking to integrate or extend TokenBridge? Check out these related projects:

- [**TokenBridge GitHub Action**](https://github.com/hupe1980/tokenbridge-action): Automate your workflows with TokenBridge using GitHub Actions.
- [**TokenBridge Backend Example**](https://github.com/hupe1980/tokenbridge-backend-example): A practical example of how to create a TokenBridge backend application.

## 🤝 Contributing

We welcome contributions! Feel free to open issues, share feedback, or submit pull requests to improve TokenBridge.

## 📄 License

TokenBridge is licensed under the [MIT License](LICENSE).
