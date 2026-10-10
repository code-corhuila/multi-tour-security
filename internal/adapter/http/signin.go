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
	if mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mediaType != "application/json" {
		writeError(w, r, http.StatusUnsupportedMediaType, "UNSUPPORTED_MEDIA_TYPE", "the body must be application/json")
		return
	}
	var body signInBody
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxSignInBody))
	decoder.DisallowUnknownFields()
	err := decoder.Decode(&body)
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
			writeError(w, r, http.StatusRequestEntityTooLarge, "PAYLOAD_TOO_LARGE", "the body is larger than 4 KB")
			return
		}
		writeError(w, r, http.StatusBadRequest, "VALIDATION_ERROR", "the body must be a JSON object with an e-mail and a password")
		return
	}
	if body.Email == nil || body.Password == nil {
		writeError(w, r, http.StatusBadRequest, "VALIDATION_ERROR", "the body must be a JSON object with an e-mail and a password")
		return
	}

	tokens, err := call(r.Context(), signin.Request{
		TenantIdentifier: identifier, Email: *body.Email, Password: *body.Password, CorrelationID: traceID(r.Context()),
	})
	switch {
	case errors.Is(err, signin.ErrRefused):
		writeError(w, r, http.StatusUnauthorized, "UNAUTHORIZED", "authentication failed")
	case errors.Is(err, signin.ErrInvalidRequest):
		writeError(w, r, http.StatusBadRequest, "VALIDATION_ERROR", "the e-mail or the password is not valid")
	case err != nil:
		s.logger.ErrorContext(r.Context(), "sign-in failed", "traceId", traceID(r.Context()), "reason", err.Error())
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
