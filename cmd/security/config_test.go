package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
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
	garbage := filepath.Join(t.TempDir(), "garbage.pem")
	if err := os.WriteFile(garbage, []byte("not a pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := map[string]map[string]string{
		"missing_private_key":      {"JWT_PRIVATE_KEY_FILE": ""},
		"missing_public_key":       {"JWT_PUBLIC_KEY_FILE": ""},
		"missing_database_url":     {"DATABASE_URL": ""},
		"url_without_password":     {"DATABASE_URL": "postgres://security_app@postgres:5432/multitour"},
		"unreadable_private_key":   {"JWT_PRIVATE_KEY_FILE": filepath.Join(t.TempDir(), "absent.pem")},
		"private_key_not_a_pem":    {"JWT_PRIVATE_KEY_FILE": garbage},
		"public_key_not_a_pem":     {"JWT_PUBLIC_KEY_FILE": garbage},
		"public_key_of_another":    {"JWT_PUBLIC_KEY_FILE": other.public},
		"key_smaller_than_2048":    {"JWT_PRIVATE_KEY_FILE": writeKeys(t, 1024).private},
		"unparseable_database_url": {"DATABASE_URL": "postgres://security_app:" + secret + "@bad host/%zz"},
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
