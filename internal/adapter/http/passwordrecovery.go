package httpadapter

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/account"
	"github.com/code-corhuila/multi-tour-security/internal/core/recoverpassword"
)

// resetTimeout bounds the reset of a password, which hashes the new one and writes.
const resetTimeout = 15 * time.Second

// RecoveryRequester is what the routes that ask for a recovery code need from their use case.
type RecoveryRequester interface {
	Request(ctx context.Context, r recoverpassword.RequestCode) error
}

// PasswordResetter is what the routes that reset a password need from their use case.
type PasswordResetter interface {
	Reset(ctx context.Context, r recoverpassword.Reset) error
}

// WithPasswordRecovery registers the four public routes of the password recovery, two for a tenant and two for the platform
// (HU-SEC-004). A person who forgot the password has no token.
func WithPasswordRecovery(requester RecoveryRequester, resetter PasswordResetter, background *Background) Option {
	return func(s *server) {
		s.recoveryRequester, s.passwordResetter, s.background = requester, resetter, background
	}
}

type recoveryRequestBody struct {
	Email *string `json:"email"`
}

type resetBody struct {
	Email                   *string `json:"email"`
	Code                    *string `json:"code"`
	NewPassword             *string `json:"newPassword"`
	NewPasswordConfirmation *string `json:"newPasswordConfirmation"`
}

// askForCode answers 202 to every well-formed request before anything is looked up, and does the work afterwards: the time
// of the answer, its body and its status are the same whether the account exists, is pending, is inactive or has already
// received three codes, so the route tells nobody which e-mails have an account. Only a request that cannot be an e-mail is
// refused, which says nothing about any account; an identifier that cannot be a tenant is answered 202 and asked of nobody.
func (s *server) askForCode(platform bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body recoveryRequestBody
		if !readJSON(w, r, &body) {
			return
		}
		if body.Email == nil {
			writeError(w, r, http.StatusBadRequest, "VALIDATION_ERROR", "the body must be a JSON object with an email")
			return
		}
		email := account.NormalizeEmail(*body.Email)
		if !account.ValidEmail(email) {
			writeError(w, r, http.StatusBadRequest, "VALIDATION_ERROR", "the email is not valid")
			return
		}
		identifier := r.PathValue("identifier")
		if platform || validIdentifier(identifier) {
			trace := traceID(r.Context())
			request := recoverpassword.RequestCode{TenantIdentifier: identifier, Platform: platform, Email: email, CorrelationID: trace}
			s.background.Go(trace, func(ctx context.Context) {
				if err := s.recoveryRequester.Request(ctx, request); err != nil {
					// only the type: the text of a driver error can quote the e-mail
					s.logger.ErrorContext(ctx, "asking for a recovery code failed", "traceId", trace, "errorType", fmt.Sprintf("%T", err))
				}
			})
		}
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusAccepted)
	}
}

// resetPassword is the only place where the answer of a reset becomes HTTP. Every refused code is one single 422 whatever
// the reason, a field that cannot be what it must be is a 400 that names it, and the cause of an unexpected failure goes to
// the log by its type, with the trace id. The use case runs on a context that outlives the request: a guess followed by a
// closed connection must still be counted toward the five tries of the code.
func (s *server) resetPassword(platform bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body resetBody
		if !readJSON(w, r, &body) {
			return
		}
		for _, f := range []struct {
			name  string
			value *string
		}{{"email", body.Email}, {"code", body.Code}, {"newPassword", body.NewPassword}, {"newPasswordConfirmation", body.NewPasswordConfirmation}} {
			if f.value == nil {
				refuseResetField(w, r, f.name)
				return
			}
		}
		identifier := r.PathValue("identifier")
		if !platform && !validIdentifier(identifier) {
			writeError(w, r, http.StatusBadRequest, "VALIDATION_ERROR", "the identifier of the tenant is not valid")
			return
		}
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), resetTimeout)
		defer cancel()
		err := s.passwordResetter.Reset(ctx, recoverpassword.Reset{
			TenantIdentifier: identifier, Platform: platform, Email: *body.Email, Code: *body.Code,
			NewPassword: *body.NewPassword, Confirmation: *body.NewPasswordConfirmation, CorrelationID: traceID(r.Context()),
		})
		var field *recoverpassword.FieldError
		switch {
		case err == nil:
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusNoContent)
		case errors.As(err, &field):
			refuseResetField(w, r, field.Field)
		case errors.Is(err, recoverpassword.ErrTenantNotFound):
			writeError(w, r, http.StatusNotFound, "NOT_FOUND", "the tenant does not exist")
		case errors.Is(err, recoverpassword.ErrCodeRefused):
			refuseRule(w, r, "the code does not work, ask for a new one")
		default:
			s.fail(w, r, "resetting the password", err)
		}
	}
}

// refuseResetField answers the 400 of a field of the reset that is missing or cannot be what it must be. It names the field
// and never quotes its value: the value is a code or a password.
func refuseResetField(w http.ResponseWriter, r *http.Request, field string) {
	writeEnvelope(w, r, http.StatusBadRequest, errorBody{Error: "VALIDATION_ERROR", Message: "the request is not valid",
		Details: []fieldDetail{{Field: field, Message: "is missing or not valid"}}})
}
