package httpadapter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/core/account"
	"github.com/code-corhuila/multi-tour-security/internal/core/createaccount"
	"github.com/code-corhuila/multi-tour-security/internal/core/port"
	"github.com/code-corhuila/multi-tour-security/internal/core/tenant"
)

// AccountCreator is what the routes that make accounts need from the use case, so a test can replace it.
type AccountCreator interface {
	Create(ctx context.Context, c createaccount.Command) (port.Registered, bool, error)
}

// TenantFinder resolves the identifier of a link to the copy of its tenant.
type TenantFinder interface {
	FindByIdentifier(ctx context.Context, identifier string) (tenant.Copy, bool, error)
}

// WithCreateAccount registers the public route where a person creates the account of a Final Customer.
func WithCreateAccount(service AccountCreator, tenants TenantFinder) Option {
	return func(s *server) { s.accounts, s.accountTenants = service, tenants }
}

type customerBody struct {
	FirstName            string `json:"firstName"`
	LastName             string `json:"lastName"`
	Email                string `json:"email"`
	Phone                string `json:"phone"`
	Password             string `json:"password"`
	PasswordConfirmation string `json:"passwordConfirmation"`
}

// createCustomerAccount takes the tenant from the link and nothing in the body can change it. A missing field arrives
// empty and the use case refuses it by name, so the rules of the fields live in one place.
func (s *server) createCustomerAccount(w http.ResponseWriter, r *http.Request) {
	identifier := r.PathValue("identifier")
	if !validIdentifier(identifier) {
		// nothing that is not an identifier reaches the store
		s.answerAccount(w, r, port.Registered{}, false, createaccount.ErrTenantNotFound)
		return
	}
	var body customerBody
	if !readJSON(w, r, &body) {
		return
	}
	t, found, err := s.accountTenants.FindByIdentifier(r.Context(), identifier)
	if err == nil && !found {
		err = createaccount.ErrTenantNotFound
	}
	if err != nil {
		s.answerAccount(w, r, port.Registered{}, false, err)
		return
	}
	reg, created, err := s.accounts.Create(r.Context(), createaccount.Command{
		Kind: createaccount.Customer, TenantID: t.TenantID, FirstName: body.FirstName, LastName: body.LastName,
		Email: body.Email, Phone: body.Phone, Password: body.Password, Confirmation: body.PasswordConfirmation,
		IdempotencyKey: r.Header.Get("Idempotency-Key"),
	})
	s.answerAccount(w, r, reg, created, err)
}

// accountBody is the AccountResponse of the contract. The entity is never serialized: this object has no field for a
// password, a hash or a temporary credential.
type accountBody struct {
	AccountID     string    `json:"accountId"`
	TenantID      string    `json:"tenantId"`
	FullName      string    `json:"fullName,omitempty"`
	Email         string    `json:"email"`
	Phone         string    `json:"phone,omitempty"`
	Roles         []string  `json:"roles"`
	AccountStatus string    `json:"accountStatus"`
	EmailVerified bool      `json:"emailVerified"`
	CreatedAt     time.Time `json:"createdAt"`
}

// answerAccount is the only place where the answer of the use case that makes accounts becomes HTTP: 201 for a new
// account, 200 for the repeat of a key, and every refusal in the common envelope. The cause of an unexpected failure
// goes to the log with the trace id and never to the caller.
func (s *server) answerAccount(w http.ResponseWriter, r *http.Request, reg port.Registered, created bool, err error) {
	var invalid *createaccount.FieldError
	var out accountBody
	if err == nil {
		out, err = toAccountBody(reg)
	}
	switch {
	case errors.As(err, &invalid):
		writeEnvelope(w, r, http.StatusBadRequest, errorBody{Error: "VALIDATION_ERROR", Message: "the request is not valid",
			Details: []fieldDetail{{Field: invalid.Field, Message: invalid.Err.Error()}}})
	case errors.Is(err, createaccount.ErrTenantNotFound):
		writeError(w, r, http.StatusNotFound, "NOT_FOUND", "the tenant does not exist")
	case errors.Is(err, createaccount.ErrTenantNotActive):
		writeError(w, r, http.StatusUnprocessableEntity, "BUSINESS_RULE_VIOLATION", "the tenant is not active")
	case errors.Is(err, port.ErrEmailTaken):
		// the details tell the portal a taken e-mail from an inactive tenant, whose 422 carries none
		writeEnvelope(w, r, http.StatusUnprocessableEntity, errorBody{Error: "BUSINESS_RULE_VIOLATION",
			Message: "the e-mail is already in use in this tenant", Details: []fieldDetail{{Field: "email", Message: "already in use"}}})
	case err != nil:
		// only the type: the text of a driver error can quote the e-mail of the row that failed
		s.logger.ErrorContext(r.Context(), "creating an account failed", "traceId", traceID(r.Context()), "errorType", fmt.Sprintf("%T", err))
		writeError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "an internal error occurred")
	default:
		status := http.StatusOK
		if created {
			status = http.StatusCreated
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(out)
	}
}

// toAccountBody refuses a status it does not know, so that a new one cannot be answered as if it were ACTIVE.
func toAccountBody(reg port.Registered) (accountBody, error) {
	var status string
	switch reg.Account.Status {
	case account.Active:
		status = "ACTIVE"
	case account.Inactive:
		status = "INACTIVE"
	default:
		return accountBody{}, errors.New("the account has a status the contract does not know")
	}
	return accountBody{
		AccountID: reg.Account.ID, TenantID: reg.Account.TenantID, FullName: reg.FullName, Email: reg.Account.EmailNormalized,
		Phone: reg.Phone, Roles: []string{reg.Role}, AccountStatus: status, EmailVerified: reg.EmailVerified,
		CreatedAt: reg.CreatedAt.UTC(),
	}, nil
}
