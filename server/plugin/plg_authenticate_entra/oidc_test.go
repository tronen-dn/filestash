package plg_authenticate_entra

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	. "github.com/mickael-kerjean/filestash/server/common"

	"github.com/golang-jwt/jwt/v5"
)

const testKid = "test-key-1"

func TestMain(m *testing.M) {
	// EncryptString/DecryptString (used by packState/unpackState) need a derived
	// key of a valid AES length; a 32-char secret yields an AES-256 key.
	InitSecretDerivate("0123456789abcdef0123456789abcdef")
	os.Exit(m.Run())
}

// newTestIssuer spins up a fake JWKS endpoint backed by a freshly generated RSA
// key and returns the key plus endpoints pointing at the test server.
func newTestIssuer(t *testing.T) (*rsa.PrivateKey, endpoints, func()) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	srv := serveJWKS(map[string]*rsa.PublicKey{testKid: &key.PublicKey})
	ep := endpoints{
		jwks:   srv.URL,
		issuer: "https://login.microsoftonline.com/test-tenant/v2.0",
	}
	cleanup := func() {
		srv.Close()
		jwksMu.Lock()
		delete(jwksCache, ep.jwks)
		jwksMu.Unlock()
	}
	return key, ep, cleanup
}

func serveJWKS(keys map[string]*rsa.PublicKey) *httptest.Server {
	doc := jwksDocument{}
	for kid, pub := range keys {
		doc.Keys = append(doc.Keys, jwk{
			Kid: kid,
			Kty: "RSA",
			N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		})
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	}))
}

func signToken(t *testing.T, key *rsa.PrivateKey, claims jwt.MapClaims, withKid bool) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	if withKid {
		tok.Header["kid"] = testKid
	}
	signed, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed
}

func baseClaims(ep endpoints, aud, nonce string) jwt.MapClaims {
	return jwt.MapClaims{
		"iss":                ep.issuer,
		"aud":                aud,
		"exp":                time.Now().Add(time.Hour).Unix(),
		"iat":                time.Now().Add(-time.Minute).Unix(),
		"nonce":              nonce,
		"sub":                "subject-123",
		"oid":                "object-id-123",
		"preferred_username": "alice@example.com",
		"name":               "Alice Example",
		"tid":                "test-tenant",
	}
}

// ---- ID token validation -------------------------------------------------

func TestValidateIDToken_Valid(t *testing.T) {
	key, ep, cleanup := newTestIssuer(t)
	defer cleanup()

	token := signToken(t, key, baseClaims(ep, "client-abc", "nonce-xyz"), true)
	claims, err := validateIDToken(token, ep, "client-abc", "nonce-xyz")
	if err != nil {
		t.Fatalf("expected valid token, got error: %v", err)
	}
	if claims["preferred_username"] != "alice@example.com" {
		t.Fatalf("unexpected claims: %v", claims)
	}
}

func TestValidateIDToken_WrongAudience(t *testing.T) {
	key, ep, cleanup := newTestIssuer(t)
	defer cleanup()

	token := signToken(t, key, baseClaims(ep, "someone-else", "nonce-xyz"), true)
	if _, err := validateIDToken(token, ep, "client-abc", "nonce-xyz"); err == nil {
		t.Fatal("expected audience mismatch to be rejected")
	}
}

func TestValidateIDToken_WrongIssuer(t *testing.T) {
	key, ep, cleanup := newTestIssuer(t)
	defer cleanup()

	claims := baseClaims(ep, "client-abc", "nonce-xyz")
	claims["iss"] = "https://login.microsoftonline.com/other-tenant/v2.0"
	token := signToken(t, key, claims, true)
	if _, err := validateIDToken(token, ep, "client-abc", "nonce-xyz"); err == nil {
		t.Fatal("expected issuer mismatch to be rejected")
	}
}

func TestValidateIDToken_Expired(t *testing.T) {
	key, ep, cleanup := newTestIssuer(t)
	defer cleanup()

	claims := baseClaims(ep, "client-abc", "nonce-xyz")
	claims["exp"] = time.Now().Add(-time.Hour).Unix()
	token := signToken(t, key, claims, true)
	if _, err := validateIDToken(token, ep, "client-abc", "nonce-xyz"); err == nil {
		t.Fatal("expected expired token to be rejected")
	}
}

func TestValidateIDToken_NonceMismatch(t *testing.T) {
	key, ep, cleanup := newTestIssuer(t)
	defer cleanup()

	token := signToken(t, key, baseClaims(ep, "client-abc", "nonce-xyz"), true)
	if _, err := validateIDToken(token, ep, "client-abc", "different-nonce"); err == nil {
		t.Fatal("expected nonce mismatch to be rejected")
	}
}

func TestValidateIDToken_EmptyExpectedNonceRejected(t *testing.T) {
	key, ep, cleanup := newTestIssuer(t)
	defer cleanup()

	token := signToken(t, key, baseClaims(ep, "client-abc", "nonce-xyz"), true)
	if _, err := validateIDToken(token, ep, "client-abc", ""); err == nil {
		t.Fatal("expected empty expected-nonce to be rejected (nonce check must never be skipped)")
	}
}

func TestValidateIDToken_BadSignature(t *testing.T) {
	_, ep, cleanup := newTestIssuer(t)
	defer cleanup()

	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	token := signToken(t, otherKey, baseClaims(ep, "client-abc", "nonce-xyz"), true)
	if _, err := validateIDToken(token, ep, "client-abc", "nonce-xyz"); err == nil {
		t.Fatal("expected bad signature to be rejected")
	}
}

func TestValidateIDToken_MissingKid(t *testing.T) {
	key, ep, cleanup := newTestIssuer(t)
	defer cleanup()

	token := signToken(t, key, baseClaims(ep, "client-abc", "nonce-xyz"), false)
	if _, err := validateIDToken(token, ep, "client-abc", "nonce-xyz"); err == nil {
		t.Fatal("expected token without kid to be rejected")
	}
}

func TestValidateIDToken_AlgNoneRejected(t *testing.T) {
	_, ep, cleanup := newTestIssuer(t)
	defer cleanup()

	tok := jwt.NewWithClaims(jwt.SigningMethodNone, baseClaims(ep, "client-abc", "nonce-xyz"))
	tok.Header["kid"] = testKid
	token, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("sign none token: %v", err)
	}
	if _, err := validateIDToken(token, ep, "client-abc", "nonce-xyz"); err == nil {
		t.Fatal("expected alg=none token to be rejected")
	}
}

func TestFetchJWKS_RejectsUndersizedKey(t *testing.T) {
	weakKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate weak key: %v", err)
	}
	srv := serveJWKS(map[string]*rsa.PublicKey{"weak": &weakKey.PublicKey})
	defer srv.Close()
	defer func() { jwksMu.Lock(); delete(jwksCache, srv.URL); jwksMu.Unlock() }()

	if _, err := fetchJWKS(srv.URL); err == nil {
		t.Fatal("expected a JWKS containing only a 1024-bit key to yield no usable keys")
	}
}

// ---- token exchange ------------------------------------------------------

func TestExchangeCode_Non200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"code expired"}`))
	}))
	defer srv.Close()

	ep := endpoints{token: srv.URL}
	if _, err := exchangeCode(ep, "client", "secret", "code", "https://host/cb", "verifier"); err == nil {
		t.Fatal("expected non-200 token response to be an error")
	}
}

func TestExchangeCode_RequiresIDToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"xyz"}`)) // 200 but no id_token
	}))
	defer srv.Close()

	ep := endpoints{token: srv.URL}
	if _, err := exchangeCode(ep, "client", "secret", "code", "https://host/cb", "verifier"); err == nil {
		t.Fatal("expected missing id_token to be an error")
	}
}

// ---- state & browser binding --------------------------------------------

func TestPackUnpackState_Roundtrip(t *testing.T) {
	in := oidcState{Nonce: "n", CodeVerifier: "v", Bind: "b", Exp: 123}
	packed, err := packState(in)
	if err != nil {
		t.Fatalf("packState: %v", err)
	}
	out, err := unpackState(packed)
	if err != nil {
		t.Fatalf("unpackState: %v", err)
	}
	if out != in {
		t.Fatalf("roundtrip mismatch: got %+v want %+v", out, in)
	}
}

func TestUnpackState_Tampered(t *testing.T) {
	packed, err := packState(oidcState{Nonce: "n", Bind: "b", Exp: 123})
	if err != nil {
		t.Fatalf("packState: %v", err)
	}
	// flip a character so decryption/authentication fails
	tampered := "A" + packed[1:]
	if _, err := unpackState(tampered); err == nil {
		t.Fatal("expected tampered state to be rejected")
	}
	if _, err := unpackState(""); err == nil {
		t.Fatal("expected empty state to be rejected")
	}
}

// callbackRequest builds a request carrying the binding cookie and a recorder.
func callbackRequest(t *testing.T, st oidcState, cookieValue string) (*http.Request, *httptest.ResponseRecorder, map[string]string) {
	t.Helper()
	packed, err := packState(st)
	if err != nil {
		t.Fatalf("packState: %v", err)
	}
	req := httptest.NewRequest("GET", "/api/session/auth/?code=abc&state="+packed, nil)
	if cookieValue != "" {
		req.AddCookie(&http.Cookie{Name: bindCookieName, Value: cookieValue})
	}
	return req, httptest.NewRecorder(), map[string]string{"code": "abc", "state": packed}
}

func validState() oidcState {
	return oidcState{Nonce: "n", CodeVerifier: "v", Bind: "bind-secret", Exp: time.Now().Add(time.Minute).Unix()}
}

func TestConsumeFlowState_Valid(t *testing.T) {
	st := validState()
	req, res, form := callbackRequest(t, st, st.Bind)
	got, err := consumeFlowState(req, res, form, time.Now())
	if err != nil {
		t.Fatalf("expected valid flow, got error: %v", err)
	}
	if got.Nonce != st.Nonce || got.CodeVerifier != st.CodeVerifier {
		t.Fatalf("unexpected state returned: %+v", got)
	}
	// the binding cookie must be cleared (one-time use)
	if !cookieCleared(res) {
		t.Fatal("expected binding cookie to be cleared on consume")
	}
}

func TestConsumeFlowState_MissingCookie(t *testing.T) {
	st := validState()
	req, res, form := callbackRequest(t, st, "") // no cookie
	if _, err := consumeFlowState(req, res, form, time.Now()); err == nil {
		t.Fatal("expected missing binding cookie to be rejected (login CSRF defense)")
	}
}

func TestConsumeFlowState_MismatchedCookie(t *testing.T) {
	st := validState()
	req, res, form := callbackRequest(t, st, "attacker-value")
	if _, err := consumeFlowState(req, res, form, time.Now()); err == nil {
		t.Fatal("expected mismatched binding cookie to be rejected")
	}
}

func TestConsumeFlowState_Expired(t *testing.T) {
	st := validState()
	st.Exp = time.Now().Add(-time.Minute).Unix()
	req, res, form := callbackRequest(t, st, st.Bind)
	if _, err := consumeFlowState(req, res, form, time.Now()); err == nil {
		t.Fatal("expected expired state to be rejected")
	}
}

func TestConsumeFlowState_ReplayAfterConsume(t *testing.T) {
	st := validState()
	req, res, form := callbackRequest(t, st, st.Bind)
	if _, err := consumeFlowState(req, res, form, time.Now()); err != nil {
		t.Fatalf("first consume should succeed: %v", err)
	}
	// simulate replay in the same browser AFTER the cookie was cleared: the
	// browser would no longer send the binding cookie.
	req2 := httptest.NewRequest("GET", "/api/session/auth/?code=abc&state="+form["state"], nil)
	if _, err := consumeFlowState(req2, httptest.NewRecorder(), form, time.Now()); err == nil {
		t.Fatal("expected replay without binding cookie to be rejected")
	}
}

func cookieCleared(res *httptest.ResponseRecorder) bool {
	for _, c := range res.Result().Cookies() {
		if c.Name == bindCookieName && c.MaxAge < 0 {
			return true
		}
	}
	return false
}

// ---- redirect URI scheme -------------------------------------------------

func TestIsHTTPS(t *testing.T) {
	plain := httptest.NewRequest("GET", "http://localhost:8334/api/session/auth/", nil)
	if isHTTPS(plain) {
		t.Fatal("plain http request should not be detected as https")
	}
	proxied := httptest.NewRequest("GET", "http://localhost:8334/api/session/auth/", nil)
	proxied.Header.Set("X-Forwarded-Proto", "https")
	if !isHTTPS(proxied) {
		t.Fatal("request with X-Forwarded-Proto=https should be detected as https")
	}
	if isHTTPS(nil) {
		t.Fatal("nil request should not be detected as https")
	}
}

// ---- claim flattening ----------------------------------------------------

func TestClaimsToStringMap_EmailFallback(t *testing.T) {
	out := claimsToStringMap(jwt.MapClaims{
		"preferred_username": "bob@example.com",
		"oid":                "abc",
	})
	if out["email"] != "bob@example.com" {
		t.Fatalf("expected email fallback to preferred_username, got %q", out["email"])
	}
}
