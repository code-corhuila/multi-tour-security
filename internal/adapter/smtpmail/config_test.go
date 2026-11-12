package smtpmail_test

import (
	"testing"

	"github.com/code-corhuila/multi-tour-security/internal/adapter/smtpmail"
)

func TestD_AConfigurationThatCannotSendIsRefusedWhenItIsBuilt(t *testing.T) {
	good := smtpmail.Config{Host: "mail.example", Port: 587, From: "no-reply@multitour.example", PublicBaseURL: "https://app.multitour.example", RequireTLS: true}
	if _, err := smtpmail.New(good); err != nil {
		t.Fatalf("a good configuration: %v", err)
	}
	for name, edit := range map[string]func(*smtpmail.Config){
		"no host":               func(c *smtpmail.Config) { c.Host = "" },
		"no port":               func(c *smtpmail.Config) { c.Port = 0 },
		"port out of range":     func(c *smtpmail.Config) { c.Port = 70000 },
		"no sender":             func(c *smtpmail.Config) { c.From = "" },
		"sender is not mail":    func(c *smtpmail.Config) { c.From = "not an address" },
		"no base url":           func(c *smtpmail.Config) { c.PublicBaseURL = "" },
		"base url without host": func(c *smtpmail.Config) { c.PublicBaseURL = "https://" },
		"base url is not web":   func(c *smtpmail.Config) { c.PublicBaseURL = "ftp://app.multitour.example" },
		"user without password": func(c *smtpmail.Config) { c.User = "mailer" },
	} {
		c := good
		edit(&c)
		if _, err := smtpmail.New(c); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

func TestD_PlainSmtpIsOnlyAllowedToTheLocalMachineOrAHostOfTheNetworkOfTheComposition(t *testing.T) {
	base := smtpmail.Config{Port: 25, From: "no-reply@multitour.example", PublicBaseURL: "https://app.multitour.example"}
	for host, ok := range map[string]bool{"mailpit": true, "localhost": true, "127.0.0.1": true, "::1": true,
		"smtp.provider.example": false, "203.0.113.7": false} {
		c := base
		c.Host = host
		_, err := smtpmail.New(c)
		if (err == nil) != ok {
			t.Fatalf("plain SMTP to %s: err = %v, want allowed=%v", host, err, ok)
		}
	}
	c := base
	c.Host, c.RequireTLS = "smtp.provider.example", true
	if _, err := smtpmail.New(c); err != nil {
		t.Fatalf("TLS to a provider: %v", err)
	}
	c.PublicBaseURL = "http://app.multitour.example"
	if _, err := smtpmail.New(c); err == nil {
		t.Fatal("a link that travels over plain http was accepted while TLS is required")
	}
}

func TestD_TheBaseUrlCannotCarryWhatBreaksTheLink(t *testing.T) {
	for _, base := range []string{"https://app.multitour.example/?x=1", "https://app.multitour.example/#top", "https://user:pw@app.multitour.example"} {
		c := smtpmail.Config{Host: "mailpit", Port: 1025, From: "no-reply@multitour.example", PublicBaseURL: base}
		if _, err := smtpmail.New(c); err == nil {
			t.Fatalf("%s was accepted", base)
		}
	}
}
