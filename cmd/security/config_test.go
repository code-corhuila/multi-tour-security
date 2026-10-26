package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const secret = "s3cr3t-password"

type keyFiles struct{ private, public string }

func writeKeys(t *testing.T, bits int) keyFiles {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	files := keyFiles{filepath.Join(dir, "private.pem"), filepath.Join(dir, "public.pem")}
	for path, block := range map[string]*pem.Block{
		files.private: {Type: "PRIVATE KEY", Bytes: privateDER},
		files.public:  {Type: "PUBLIC KEY", Bytes: publicDER},
	} {
		if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return files
}

func environment(files keyFiles, overrides map[string]string) func(string) string {
	env := map[string]string{
		"DATABASE_URL":         "postgres://security_app:" + secret + "@postgres:5432/multitour",
		"JWT_PRIVATE_KEY_FILE": files.private,
		"JWT_PUBLIC_KEY_FILE":  files.public,
		"SMTP_HOST":            "mailpit",
		"SMTP_PORT":            "1025",
		"SMTP_FROM":            "no-reply@multitour.example",
		"SMTP_REQUIRE_TLS":     "false",
		"PUBLIC_BASE_URL":      "http://localhost:4200",
	}
	for name, value := range overrides {
		env[name] = value
	}
	return func(name string) string { return env[name] }
}

func TestC_StartupAcceptsAValidConfiguration(t *testing.T) {
	cfg, err := loadConfig(environment(writeKeys(t, 2048), nil), os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.port != "8086" {
		t.Fatalf("port = %q, want the default 8086", cfg.port)
	}
	cfg, err = loadConfig(environment(writeKeys(t, 2048), map[string]string{"HTTP_PORT": "9000"}), os.ReadFile)
	if err != nil || cfg.port != "9000" {
		t.Fatalf("HTTP_PORT must override the default, got %q (%v)", cfg.port, err)
	}
}

func TestC_StartupFailsWithoutItsKeys(t *testing.T) {
	files := writeKeys(t, 2048)
	other := writeKeys(t, 2048)
	small := writeKeys(t, 1024)
	garbage := filepath.Join(t.TempDir(), "garbage.pem")
	if err := os.WriteFile(garbage, []byte("not a pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := map[string]map[string]string{
		"missing_private_key":       {"JWT_PRIVATE_KEY_FILE": ""},
		"missing_public_key":        {"JWT_PUBLIC_KEY_FILE": ""},
		"missing_database_url":      {"DATABASE_URL": ""},
		"url_without_password":      {"DATABASE_URL": "postgres://security_app@postgres:5432/multitour"},
		"unreadable_private_key":    {"JWT_PRIVATE_KEY_FILE": filepath.Join(t.TempDir(), "absent.pem")},
		"private_key_not_a_pem":     {"JWT_PRIVATE_KEY_FILE": garbage},
		"public_key_not_a_pem":      {"JWT_PUBLIC_KEY_FILE": garbage},
		"public_key_of_another":     {"JWT_PUBLIC_KEY_FILE": other.public},
		"key_smaller_than_2048":     {"JWT_PRIVATE_KEY_FILE": small.private, "JWT_PUBLIC_KEY_FILE": small.public},
		"database_url_not_postgres": {"DATABASE_URL": "http://security_app:" + secret + "@postgres:5432/multitour"},
		"unparseable_database_url":  {"DATABASE_URL": "postgres://security_app:" + secret + "@bad host/%zz"},
	}
	for name, overrides := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := loadConfig(environment(files, overrides), os.ReadFile)
			if err == nil {
				t.Fatal("start-up must fail")
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("the error leaks the password: %v", err)
			}
		})
	}
}

func TestC_StartupRejectsAnInvalidPort(t *testing.T) {
	files := writeKeys(t, 2048)
	for _, port := range []string{"abc", "0", "70000", "80 ", "1.2.3.4:80"} {
		t.Run(port, func(t *testing.T) {
			_, err := loadConfig(environment(files, map[string]string{"HTTP_PORT": port}), os.ReadFile)
			if err == nil || strings.Contains(err.Error(), port) {
				t.Fatalf("an invalid port must fail without repeating it, got %v", err)
			}
		})
	}
}

func TestC_ConfigNeverPrintsItsSecrets(t *testing.T) {
	cfg, err := loadConfig(environment(writeKeys(t, 2048), nil), os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		if printed := fmt.Sprintf(verb, cfg); strings.Contains(printed, secret) {
			t.Fatalf("%s prints the password: %s", verb, printed)
		}
	}
}

func TestC_StartupReadsTheMailSettingsAndRequiresTlsUnlessTheEnvironmentSaysItIsNot(t *testing.T) {
	files := writeKeys(t, 2048)
	cfg, err := loadConfig(environment(files, nil), os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.mail.Host != "mailpit" || cfg.mail.Port != 1025 || cfg.mail.From != "no-reply@multitour.example" || cfg.mail.RequireTLS || cfg.mail.PublicBaseURL != "http://localhost:4200" {
		t.Fatalf("mail = %+v", cfg.mail)
	}
	provider := map[string]string{"SMTP_HOST": "smtp.provider.example", "SMTP_PORT": "587", "SMTP_USER": "mailer", "SMTP_PASSWORD": secret,
		"SMTP_REQUIRE_TLS": "", "PUBLIC_BASE_URL": "https://app.multitour.example"}
	cfg, err = loadConfig(environment(files, provider), os.ReadFile)
	if err != nil || !cfg.mail.RequireTLS || cfg.mail.User != "mailer" || cfg.mail.Password != secret {
		t.Fatalf("an unset SMTP_REQUIRE_TLS is true: %+v %v", cfg.mail, err)
	}
	for _, shown := range []string{fmt.Sprintf("%v", cfg), fmt.Sprintf("%+v", cfg), fmt.Sprintf("%#v", cfg)} {
		if strings.Contains(shown, secret) {
			t.Fatalf("a printed configuration shows the password of the mail server: %s", shown)
		}
	}
}

func TestC_StartupRefusesAMailConfigurationThatCannotSendOrWouldSendInClear(t *testing.T) {
	files := writeKeys(t, 2048)
	cases := map[string]map[string]string{
		"no host":                       {"SMTP_HOST": ""},
		"no port":                       {"SMTP_PORT": ""},
		"port that is not a number":     {"SMTP_PORT": "abc"},
		"no sender":                     {"SMTP_FROM": ""},
		"no base url":                   {"PUBLIC_BASE_URL": ""},
		"tls that is neither":           {"SMTP_REQUIRE_TLS": "maybe"},
		"a provider without tls":        {"SMTP_HOST": "smtp.provider.example", "SMTP_REQUIRE_TLS": "false"},
		"a provider and http":           {"SMTP_HOST": "smtp.provider.example", "SMTP_REQUIRE_TLS": "true"},
		"a user without a password":     {"SMTP_USER": "mailer"},
		"a password without a user":     {"SMTP_PASSWORD": secret},
		"a provider padded with spaces": {"SMTP_HOST": " smtp.provider.example ", "SMTP_REQUIRE_TLS": "false"},
	}
	for name, overrides := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := loadConfig(environment(files, overrides), os.ReadFile)
			if err == nil {
				t.Fatal("start-up must fail")
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("the error leaks the password: %v", err)
			}
		})
	}
}

func TestC_AMissingVariableIsNamedAndTheMessageSaysWhereToSetIt(t *testing.T) {
	_, err := loadConfig(environment(writeKeys(t, 2048), map[string]string{"SMTP_HOST": "", "PUBLIC_BASE_URL": ""}), os.ReadFile)
	if err == nil || !strings.Contains(err.Error(), "SMTP_HOST") || !strings.Contains(err.Error(), "PUBLIC_BASE_URL") || !strings.Contains(err.Error(), "env/") {
		t.Fatalf("err = %v, want the names of the variables and the file where they are set", err)
	}
}
