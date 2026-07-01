package plg_authenticate_entra

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	. "github.com/mickael-kerjean/filestash/server/common"

	"github.com/golang-jwt/jwt/v5"
)

const microsoftLoginHost = "https://login.microsoftonline.com"

// minRSAKeyBits is the smallest RSA modulus we accept from the JWKS. Microsoft
// signing keys are 2048 bits; anything smaller is rejected as a downgrade.
const minRSAKeyBits = 2048

// secureToken returns a base64url string built from nBytes of cryptographically
// secure randomness. Unlike common.RandomString it surfaces a crypto/rand
// failure as an error instead of silently degrading, so the caller can abort
// the authentication flow rather than emit a guessable nonce/verifier/state.
func secureToken(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// endpoints holds the per-tenant Entra ID OIDC URLs.
type endpoints struct {
	authorize string
	token     string
	jwks      string
	issuer    string
}

func tenantEndpoints(tenantID string) endpoints {
	base := microsoftLoginHost + "/" + url.PathEscape(tenantID)
	return endpoints{
		authorize: base + "/oauth2/v2.0/authorize",
		token:     base + "/oauth2/v2.0/token",
		jwks:      base + "/discovery/v2.0/keys",
		issuer:    base + "/v2.0",
	}
}

// tokenResponse is the subset of the token endpoint response we rely on.
type tokenResponse struct {
	IDToken          string `json:"id_token"`
	AccessToken      string `json:"access_token"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// exchangeCode swaps an authorization code for tokens against the token
// endpoint. The client secret only ever travels in the POST body (never a URL)
// and is not echoed back in any returned error.
func exchangeCode(ep endpoints, clientID, clientSecret, code, redirectURI, codeVerifier string) (tokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("code_verifier", codeVerifier)

	req, err := http.NewRequest("POST", ep.token, strings.NewReader(form.Encode()))
	if err != nil {
		return tokenResponse{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := HTTPClient().Do(req)
	if err != nil {
		return tokenResponse{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return tokenResponse{}, err
	}
	var tr tokenResponse
	if jsonErr := json.Unmarshal(body, &tr); jsonErr != nil {
		// non-json body: surface the status without leaking the body content
		return tokenResponse{}, fmt.Errorf("token endpoint returned a non-json response (status %d)", resp.StatusCode)
	}
	if tr.Error != "" {
		return tokenResponse{}, fmt.Errorf("token endpoint error: %s - %s", tr.Error, tr.ErrorDescription)
	}
	if resp.StatusCode != http.StatusOK {
		return tokenResponse{}, fmt.Errorf("token endpoint returned status %d", resp.StatusCode)
	}
	if tr.IDToken == "" {
		return tokenResponse{}, fmt.Errorf("token endpoint did not return an id_token")
	}
	return tr, nil
}

// ---- JWKS handling -------------------------------------------------------

type jwk struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type jwksDocument struct {
	Keys []jwk `json:"keys"`
}

type jwksCacheEntry struct {
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
}

var (
	jwksMu sync.Mutex
	// jwksCache is keyed by the tenant JWKS URL, so its size is bounded by the
	// number of distinct tenants ever configured (typically one). Entries are
	// refreshed in place on each successful refetch and never accumulate per
	// kid, so no explicit eviction is required for the expected single-tenant
	// deployment.
	jwksCache = map[string]jwksCacheEntry{}
)

const (
	jwksTTL        = time.Hour
	jwksStaleGrace = 2 * time.Hour // accept cached keys this long past a failed refetch
)

// signingKey returns the RSA public key matching kid for the given tenant,
// refetching the JWKS document when the cache is stale or the kid is unknown.
func signingKey(jwksURL, kid string) (*rsa.PublicKey, error) {
	jwksMu.Lock()
	defer jwksMu.Unlock()

	entry, ok := jwksCache[jwksURL]
	if ok && time.Since(entry.fetchedAt) < jwksTTL {
		if key, found := entry.keys[kid]; found {
			return key, nil
		}
	}
	// cache miss, stale, or unknown kid: refetch once
	keys, err := fetchJWKS(jwksURL)
	if err != nil {
		// bounded stale fallback: only serve cached keys for a short grace
		// window after a failed refetch, and make the degraded mode visible.
		if ok && time.Since(entry.fetchedAt) < jwksStaleGrace {
			if key, found := entry.keys[kid]; found {
				Log.Warning("plg_authenticate_entra::jwks using stale cached key (refetch failed: %s)", err.Error())
				return key, nil
			}
		}
		return nil, err
	}
	jwksCache[jwksURL] = jwksCacheEntry{keys: keys, fetchedAt: time.Now()}
	if key, found := keys[kid]; found {
		return key, nil
	}
	return nil, fmt.Errorf("no signing key found for kid %q", kid)
}

func fetchJWKS(jwksURL string) (map[string]*rsa.PublicKey, error) {
	req, err := http.NewRequest("GET", jwksURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := HTTPClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks endpoint returned status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var doc jwksDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	keys := map[string]*rsa.PublicKey{}
	for _, k := range doc.Keys {
		if k.Kty != "RSA" || k.Kid == "" {
			continue
		}
		pub, err := jwkToRSA(k)
		if err != nil {
			continue
		}
		if pub.N.BitLen() < minRSAKeyBits {
			Log.Warning("plg_authenticate_entra::jwks ignoring undersized RSA key kid=%s bits=%d", k.Kid, pub.N.BitLen())
			continue
		}
		keys[k.Kid] = pub
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("jwks document contained no usable RSA keys")
	}
	return keys, nil
}

func jwkToRSA(k jwk) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, err
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(new(big.Int).SetBytes(eBytes).Int64()),
	}, nil
}

// ---- ID token validation -------------------------------------------------

// validateIDToken cryptographically verifies the id_token and the security
// invariants (signature, issuer, audience, expiry, nonce) before returning its
// claims. An empty expectedNonce is treated as a programming error and rejected
// so nonce validation can never be silently skipped.
func validateIDToken(rawIDToken string, ep endpoints, clientID, expectedNonce string) (jwt.MapClaims, error) {
	if expectedNonce == "" {
		return nil, fmt.Errorf("refusing to validate id_token without an expected nonce")
	}
	claims := jwt.MapClaims{}
	keyFunc := func(token *jwt.Token) (interface{}, error) {
		kid, _ := token.Header["kid"].(string)
		if kid == "" {
			return nil, fmt.Errorf("id_token is missing a kid header")
		}
		return signingKey(ep.jwks, kid)
	}
	_, err := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(ep.issuer),
		jwt.WithAudience(clientID),
		jwt.WithExpirationRequired(),
	).ParseWithClaims(rawIDToken, claims, keyFunc)
	if err != nil {
		return nil, err
	}
	if nonce, _ := claims["nonce"].(string); nonce != expectedNonce {
		return nil, fmt.Errorf("id_token nonce mismatch")
	}
	return claims, nil
}

// claimsToStringMap flattens the scalar id_token claims into the attribute map
// exposed to the attribute-mapping section, deriving an "email" fallback from
// the common alternatives when the email claim is absent.
func claimsToStringMap(claims jwt.MapClaims) map[string]string {
	out := map[string]string{}
	for key, value := range claims {
		switch v := value.(type) {
		case string:
			out[key] = v
		case float64:
			out[key] = fmt.Sprintf("%v", v)
		case bool:
			out[key] = fmt.Sprintf("%t", v)
		}
	}
	if out["email"] == "" {
		for _, alt := range []string{"preferred_username", "upn"} {
			if out[alt] != "" {
				out["email"] = out[alt]
				break
			}
		}
	}
	return out
}
