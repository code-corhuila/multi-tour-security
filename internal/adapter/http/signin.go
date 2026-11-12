package httpadapter

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"

	"github.com/code-corhuila/multi-tour-security/internal/core/signin"
)

// maxSignInBody is far above the largest valid request (an e-mail of 254 and a password of 128 characters).
const maxSignInBody = 4096

// SignInService is what the routes need from the use case, so a test can replace it.
type SignInService interface {
	SignIn(ctx context.Context, r signin.Request) (signin.Tokens, error)
	SignInPlatform(ctx context.Context, r signin.Request) (signin.Tokens, error)
}

// Option changes what New registers.
type Option func(*server)

// WithSignIn registers the two public sign-in routes. They are the only ones that need no token.
func WithSignIn(service SignInService) Option {
	return func(s *server) { s.signIn = service }
}

type signInBody struct {
	Email    *string `json:"email"`
	Password *string `json:"password"`
}

type sessionBody struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken,omitempty"`
	TokenType    string `json:"tokenType"`
	ExpiresIn    int    `json:"expiresIn"`
}

func (s *server) signInTenant(w http.ResponseWriter, r *http.Request) {
	s.signInWith(w, r, r.PathValue("identifier"), s.signIn.SignIn)
}

func (s *server) signInPlatform(w http.ResponseWriter, r *http.Request) {
	s.signInWith(w, r, "", s.signIn.SignInPlatform)
}

// signInWith reads the body strictly, calls the use case and is the only place where its answer becomes HTTP. A
// refusal is always the same 401, and the cause of any other failure goes to the log with the trace id.
func (s *server) signInWith(w http.ResponseWriter, r *http.Request, identifier string,
	call func(context.Context, signin.Request) (signin.Tokens, error)) {
	var body signInBody
	if !readJSON(w, r, &body) {
		return
	}
	if body.Email == nil || body.Password == nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_ERROR", "the body must be a JSON object with an e-mail and a password")
		return
	}
	tokens, err := call(r.Context(), signin.Request{
		TenantIdentifier: identifier, Email: *body.Email, Password: *body.Password, CorrelationID: traceID(r.Context()),
	})
	s.answerTokens(w, r, tokens, err, "sign-in")
}

// readJSON reads the body of a public route strictly and answers the error itself when it cannot: only
// application/json, 4 KB at most (judged by what arrives, so a chunked body too), one document and no unknown field.
func readJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	return readJSONWith(w, r, dst, maxSignInBody, true)
}

// readJSONWith is readJSON with the limit of the route and the choice to tolerate fields it does not name, which an
// envelope of another service needs (it grows without asking).
func readJSONWith(w http.ResponseWriter, r *http.Request, dst any, limit int64, strict bool) bool {
	if mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mediaType != "application/json" {
		writeError(w, r, http.StatusUnsupportedMediaType, "UNSUPPORTED_MEDIA_TYPE", "the body must be application/json")
		return false
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	if strict {
		decoder.DisallowUnknownFields()
	}
	err := decoder.Decode(dst)
	if err == nil {
		// one document and nothing after it
		if _, err = decoder.Token(); err == io.EOF {
			err = nil
		} else if err == nil {
			err = errors.New("data after the document")
		}
	}
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, r, http.StatusRequestEntityTooLarge, "PAYLOAD_TOO_LARGE", "the body is larger than the limit of the route")
			return false
		}
		writeError(w, r, http.StatusBadRequest, "VALIDATION_ERROR", "the body must be a JSON object with the fields of the contract")
		return false
	}
	return true
}

// answerTokens is the only place where the answer of a use case that issues tokens becomes HTTP. A refusal is always
// the same 401, and the cause of any other failure goes to the log with the trace id.
func (s *server) answerTokens(w http.ResponseWriter, r *http.Request, tokens signin.Tokens, err error, what string) {
	switch {
	case errors.Is(err, signin.ErrRefused):
		writeError(w, r, http.StatusUnauthorized, "UNAUTHORIZED", "authentication failed")
	case errors.Is(err, signin.ErrEmailNotVerified):
		// the one refusal that is not the generic 401, and only after the right password: the details let the portal offer a new link
		writeEnvelope(w, r, http.StatusForbidden, errorBody{Error: "FORBIDDEN", Message: "the e-mail of the account is not verified",
			Details: []fieldDetail{{Field: "email", Message: "EMAIL_NOT_VERIFIED"}}})
	case errors.Is(err, signin.ErrInvalidRequest):
		writeError(w, r, http.StatusBadRequest, "VALIDATION_ERROR", "the request is not valid")
	case err != nil:
		s.logger.ErrorContext(r.Context(), what+" failed", "traceId", traceID(r.Context()), "reason", err.Error())
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "an internal error occurred")
	default:
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		_ = json.NewEncoder(w).Encode(sessionBody{
			AccessToken: tokens.AccessToken, RefreshToken: tokens.RefreshToken, TokenType: "Bearer",
			ExpiresIn: int(tokens.ExpiresIn.Seconds()),
		})
	}
}

// RefreshService is what the renewal route needs from its use case.
type RefreshService interface {
	Renew(ctx context.Context, refreshToken string) (signin.Tokens, error)
}

// WithRefresh registers the public route that renews a session.
func WithRefresh(service RefreshService) Option {
	return func(s *server) { s.refresh = service }
}

type refreshBody struct {
	RefreshToken *string `json:"refreshToken"`
}

func (s *server) renew(w http.ResponseWriter, r *http.Request) {
	var body refreshBody
	if !readJSON(w, r, &body) {
		return
	}
	if body.RefreshToken == nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_ERROR", "the body must be a JSON object with a refreshToken")
		return
	}
	tokens, err := s.refresh.Renew(r.Context(), *body.RefreshToken)
	s.answerTokens(w, r, tokens, err, "renewal")
}
