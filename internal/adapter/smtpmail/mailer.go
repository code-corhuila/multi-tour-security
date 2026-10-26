package smtpmail

import (
	"context"
	"errors"

	"github.com/code-corhuila/multi-tour-security/internal/core/port"
)

var _ port.Mailer = (*Mailer)(nil)

func (m *Mailer) SendVerification(ctx context.Context, mm port.Mail) error {
	return errors.New("not implemented")
}
