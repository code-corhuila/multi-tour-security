package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/code-corhuila/multi-tour-security/internal/adapter/smtpmail"
)

const (
	// defaultPort is the one assigned to this service in 07-api/guidelines.md, section 1.1.
	defaultPort = "8086"
	// minKeyBits is the smallest RSA key the service signs or verifies with.
	minKeyBits = 2048
)

type config struct {
	port        string
	databaseURL string
	privateKey  *rsa.PrivateKey
	publicKey   *rsa.PublicKey
	mail        smtpmail.Config
}

// String and GoString keep the database password and the keys out of any printed value.
func (c config) String() string   { return "config{port: " + c.port + "}" }
func (c config) GoString() string { return c.String() }

// loadConfig reads the environment once, at start-up, and refuses to run on anything missing or
// weak. No error it returns carries the content of a secret.
func loadConfig(getenv func(string) string, readFile func(string) ([]byte, error)) (config, error) {
	var missing []string
	need := func(name string) string {
		value := getenv(name)
		if value == "" {
			missing = append(missing, name)
		}
		return value
	}
	databaseURL := need("DATABASE_URL")
	privatePath := need("JWT_PRIVATE_KEY_FILE")
	publicPath := need("JWT_PUBLIC_KEY_FILE")
	// the e-mail that carries a credential: nothing is guessed, so a service that cannot send does not start
	mailHost, mailPort, mailFrom, baseURL := need("SMTP_HOST"), need("SMTP_PORT"), need("SMTP_FROM"), need("PUBLIC_BASE_URL")
	if len(missing) > 0 {
		return config{}, fmt.Errorf("missing required variables: %s (set them in env/<environment>.env of multi-tour-infra-postgres)", strings.Join(missing, ", "))
	}
	if err := checkDatabaseURL(databaseURL); err != nil {
		return config{}, err
	}

	privateKey, err := readPrivateKey(readFile, privatePath)
	if err != nil {
		return config{}, err
	}
	publicKey, err := readPublicKey(readFile, publicPath)
	if err != nil {
		return config{}, err
	}
	if !privateKey.PublicKey.Equal(publicKey) {
		return config{}, errors.New("JWT_PUBLIC_KEY_FILE is not the public half of JWT_PRIVATE_KEY_FILE")
	}

	port := getenv("HTTP_PORT")
	if port == "" {
		port = defaultPort
	}
	if number, err := strconv.Atoi(port); err != nil || number < 1 || number > 65535 {
		return config{}, errors.New("HTTP_PORT must be a number between 1 and 65535")
	}
	mail, err := loadMail(getenv, strings.TrimSpace(mailHost), strings.TrimSpace(mailPort), strings.TrimSpace(mailFrom), strings.TrimSpace(baseURL))
	if err != nil {
		return config{}, err
	}
	return config{port: port, databaseURL: databaseURL, privateKey: privateKey, publicKey: publicKey, mail: mail}, nil
}

// loadMail reads the settings of the sender. TLS is required unless SMTP_REQUIRE_TLS says false: forgetting the variable
// never leaves the link travelling in clear. smtpmail.New has the last word on what can send; its errors name the setting,
// never its value.
func loadMail(getenv func(string) string, host, port, from, baseURL string) (smtpmail.Config, error) {
	number, err := strconv.Atoi(port)
	if err != nil {
		return smtpmail.Config{}, errors.New("SMTP_PORT must be a number")
	}
	requireTLS := true
	switch getenv("SMTP_REQUIRE_TLS") {
	case "", "true":
	case "false":
		requireTLS = false
	default:
		return smtpmail.Config{}, errors.New("SMTP_REQUIRE_TLS must be true or false")
	}
	mail := smtpmail.Config{Host: host, Port: number, User: getenv("SMTP_USER"), Password: getenv("SMTP_PASSWORD"), From: from,
		RequireTLS: requireTLS, PublicBaseURL: baseURL}
	if _, err := smtpmail.New(mail); err != nil {
		return smtpmail.Config{}, fmt.Errorf("mail settings: %w", err)
	}
	return mail, nil
}

// checkDatabaseURL demands a password: the service connects as security_app, never without one.
// The parser's own error quotes the URL, so it is replaced by a fixed message.
func checkDatabaseURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return errors.New("DATABASE_URL is not a valid URL")
	}
	if parsed.Scheme != "postgres" && parsed.Scheme != "postgresql" {
		return errors.New("DATABASE_URL must use the postgres scheme")
	}
	if password, _ := parsed.User.Password(); password == "" {
		return errors.New("DATABASE_URL must carry the password of security_app")
	}
	return nil
}

func readPrivateKey(readFile func(string) ([]byte, error), path string) (*rsa.PrivateKey, error) {
	block, err := readPEM(readFile, path, "JWT_PRIVATE_KEY_FILE")
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("JWT_PRIVATE_KEY_FILE is not a PKCS#8 private key")
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok || key.N.BitLen() < minKeyBits {
		return nil, fmt.Errorf("JWT_PRIVATE_KEY_FILE must be an RSA key of at least %d bits", minKeyBits)
	}
	return key, nil
}

func readPublicKey(readFile func(string) ([]byte, error), path string) (*rsa.PublicKey, error) {
	block, err := readPEM(readFile, path, "JWT_PUBLIC_KEY_FILE")
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errors.New("JWT_PUBLIC_KEY_FILE is not a PKIX public key")
	}
	key, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("JWT_PUBLIC_KEY_FILE must be an RSA key")
	}
	return key, nil
}

func readPEM(readFile func(string) ([]byte, error), path, variable string) (*pem.Block, error) {
	data, err := readFile(path)
	if err != nil {
		return nil, fmt.Errorf("%s cannot be read", variable)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%s is not a PEM file", variable)
	}
	return block, nil
}
