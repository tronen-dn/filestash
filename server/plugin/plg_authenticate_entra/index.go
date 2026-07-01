package plg_authenticate_entra

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	. "github.com/mickael-kerjean/filestash/server/common"
)

const (
	// bindCookieName carries the browser-binding secret that ties an in-flight
	// login to the browser that initiated it (defends against login CSRF /
	// session fixation: a callback URL captured by an attacker is useless in a
	// victim's browser because the victim has no matching cookie).
	bindCookieName = "entra_oidc_bind"
	// stateTTL bounds how long an authorization request stays valid.
	stateTTL = 10 * time.Minute
)

func init() {
	Hooks.Register.AuthenticationMiddleware("entra", Entra{})
}

type Entra struct{}

// oidcState is packed (encrypted) into the OIDC `state` parameter. Encrypting it
// with SECRET_KEY_DERIVATE_FOR_USER makes it unforgeable and tamper-proof; the
// Bind field is additionally matched against an HttpOnly cookie at callback time
// so the state cannot be replayed from a different browser, and Exp bounds its
// lifetime. The authorization code itself is single-use (enforced by Entra), and
// the bind cookie is cleared on callback, making each flow effectively one-shot.
type oidcState struct {
	Nonce        string `json:"nonce"`
	CodeVerifier string `json:"code_verifier"`
	Bind         string `json:"bind"`
	Exp          int64  `json:"exp"`
}

func (this Entra) Setup() Form {
	return Form{
		Elmnts: []FormElement{
			{
				Name: "banner",
				Type: "hidden",
				Description: `Authenticate your users against Microsoft Entra ID (Azure AD) using the OpenID Connect authorization code flow.

In your Entra app registration, add this Web redirect URI:
    https://<your-filestash-host>/api/session/auth/

Once authenticated, the following claims are available in the attribute mapping section:
{{ .email }}, {{ .preferred_username }}, {{ .name }}, {{ .oid }}, {{ .sub }}, {{ .upn }}, {{ .tid }}`,
			},
			{
				Name:  "type",
				Type:  "hidden",
				Value: "entra",
			},
			{
				Name:        "tenant_id",
				Type:        "text",
				Value:       "",
				Placeholder: "Directory (tenant) ID",
			},
			{
				Name:        "client_id",
				Type:        "text",
				Value:       "",
				Placeholder: "Application (client) ID",
			},
			{
				Name:        "client_secret",
				Type:        "password",
				Value:       "",
				Placeholder: "Client secret",
			},
			{
				Name:        "scope",
				Type:        "text",
				Value:       "openid profile email",
				Placeholder: "openid profile email",
			},
			{
				Name:        "prompt",
				Type:        "text",
				Value:       "",
				Placeholder: "prompt (optional): select_account | login | none",
			},
		},
	}
}

func (this Entra) EntryPoint(idpParams map[string]string, req *http.Request, res http.ResponseWriter) error {
	tenantID := strings.TrimSpace(idpParams["tenant_id"])
	clientID := strings.TrimSpace(idpParams["client_id"])
	if tenantID == "" || clientID == "" {
		return ErrNotValid
	}
	scope := strings.TrimSpace(idpParams["scope"])
	if scope == "" {
		scope = "openid profile email"
	}

	nonce, err := secureToken(32)
	if err != nil {
		return err
	}
	codeVerifier, err := secureToken(48)
	if err != nil {
		return err
	}
	bind, err := secureToken(32)
	if err != nil {
		return err
	}
	codeChallenge := pkceChallenge(codeVerifier)

	state, err := packState(oidcState{
		Nonce:        nonce,
		CodeVerifier: codeVerifier,
		Bind:         bind,
		Exp:          time.Now().Add(stateTTL).Unix(),
	})
	if err != nil {
		return err
	}
	http.SetCookie(res, bindCookie(req, bind, int(stateTTL.Seconds())))

	ep := tenantEndpoints(tenantID)
	q := url.Values{}
	q.Set("client_id", clientID)
	q.Set("response_type", "code")
	q.Set("response_mode", "query")
	q.Set("redirect_uri", redirectURI(req))
	q.Set("scope", scope)
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")
	// Optional OIDC `prompt`. With a single SSO-gated connection the UI silently
	// re-authenticates from an active IdP session after a local logout; setting
	// prompt=select_account (or login) forces the account picker so logout is
	// visible, without ending the user's session in other Microsoft apps.
	if prompt := strings.TrimSpace(idpParams["prompt"]); prompt != "" {
		q.Set("prompt", prompt)
	}

	http.Redirect(res, req, ep.authorize+"?"+q.Encode(), http.StatusSeeOther)
	return nil
}

func (this Entra) Callback(formData map[string]string, idpParams map[string]string, req *http.Request, res http.ResponseWriter) (map[string]string, error) {
	// the identity provider reported an error (eg: user cancelled): surface it
	// instead of bouncing back into a redirect loop.
	if e := formData["error"]; e != "" {
		Log.Warning("plg_authenticate_entra::callback idp_error error=%s description=%s", e, formData["error_description"])
		return nil, NewError("Authentication was rejected by the identity provider", 403)
	}
	if formData["code"] == "" {
		// not a real callback yet (eg: direct navigation) -> kick off the flow
		return nil, ErrAuthenticationFailed
	}

	tenantID := strings.TrimSpace(idpParams["tenant_id"])
	clientID := strings.TrimSpace(idpParams["client_id"])
	clientSecret := idpParams["client_secret"]
	if tenantID == "" || clientID == "" || clientSecret == "" {
		return nil, ErrNotValid
	}

	st, err := consumeFlowState(req, res, formData, time.Now())
	if err != nil {
		Log.Warning("plg_authenticate_entra::callback state_rejected err=%s", err.Error())
		return nil, ErrAuthenticationFailed
	}

	ep := tenantEndpoints(tenantID)
	tr, err := exchangeCode(ep, clientID, clientSecret, formData["code"], redirectURI(req), st.CodeVerifier)
	if err != nil {
		Log.Warning("plg_authenticate_entra::callback token_exchange err=%s", err.Error())
		return nil, ErrAuthenticationFailed
	}
	claims, err := validateIDToken(tr.IDToken, ep, clientID, st.Nonce)
	if err != nil {
		Log.Warning("plg_authenticate_entra::callback id_token_validation err=%s", err.Error())
		return nil, ErrAuthenticationFailed
	}
	return claimsToStringMap(claims), nil
}

// consumeFlowState validates the authorization-flow state and atomically
// consumes the browser-binding cookie. It enforces, in order: a present and
// well-formed encrypted state, expiry, and a constant-time match between the
// state's Bind value and the browser cookie. The bind cookie is always cleared
// (one-time use) before returning.
func consumeFlowState(req *http.Request, res http.ResponseWriter, formData map[string]string, now time.Time) (oidcState, error) {
	st, err := unpackState(formData["state"])
	if err != nil {
		return oidcState{}, err
	}
	// clear the binding cookie regardless of outcome so a flow cannot be replayed
	http.SetCookie(res, bindCookie(req, "", -1))

	if st.Exp == 0 || now.Unix() > st.Exp {
		return oidcState{}, ErrAuthenticationFailed
	}
	cookie, err := req.Cookie(bindCookieName)
	if err != nil || cookie.Value == "" {
		return oidcState{}, ErrAuthenticationFailed
	}
	if st.Bind == "" || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(st.Bind)) != 1 {
		return oidcState{}, ErrAuthenticationFailed
	}
	return st, nil
}

func packState(st oidcState) (string, error) {
	b, err := json.Marshal(st)
	if err != nil {
		return "", err
	}
	return EncryptString(SECRET_KEY_DERIVATE_FOR_USER, string(b))
}

func unpackState(raw string) (oidcState, error) {
	if raw == "" {
		return oidcState{}, ErrAuthenticationFailed
	}
	decrypted, err := DecryptString(SECRET_KEY_DERIVATE_FOR_USER, raw)
	if err != nil {
		return oidcState{}, err
	}
	var st oidcState
	if err := json.Unmarshal([]byte(decrypted), &st); err != nil {
		return oidcState{}, err
	}
	return st, nil
}

// bindCookie builds the short-lived browser-binding cookie. SameSite=Lax (not
// Strict) is required so the cookie is still sent on the top-level redirect back
// from login.microsoftonline.com.
func bindCookie(req *http.Request, value string, maxAge int) *http.Cookie {
	cookie := &http.Cookie{
		Name:     bindCookieName,
		Value:    value,
		MaxAge:   maxAge,
		Path:     COOKIE_PATH,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	if isHTTPS(req) {
		cookie.Secure = true
	}
	return cookie
}

func isHTTPS(req *http.Request) bool {
	if req == nil {
		return false
	}
	return req.TLS != nil || strings.EqualFold(req.Header.Get("X-Forwarded-Proto"), "https")
}

// redirectURI builds the OIDC redirect/callback URL. The scheme follows the
// incoming request so a plain-http localhost run works (Entra allows
// http://localhost), while a deployment behind a TLS-terminating proxy still
// yields https via X-Forwarded-Proto. EntryPoint and Callback both pass the
// request, so the authorize and token-exchange redirect_uri values match.
func redirectURI(req *http.Request) string {
	scheme := "https"
	if !isHTTPS(req) {
		scheme = "http"
	}
	return scheme + "://" + Config.Get("general.host").String() + WithBase("/api/session/auth/")
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
