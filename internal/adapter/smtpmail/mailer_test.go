package smtpmail_test

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/code-corhuila/multi-tour-security/internal/adapter/smtpmail"
	"github.com/code-corhuila/multi-tour-security/internal/core/port"
)

const token = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_AbCdE"

var ctx = context.Background()

func verification() port.Mail {
	return port.Mail{To: "ana@example.com", TenantName: "Travesía Natural SAS", TenantIdentifier: "travesia", Token: token}
}

// delivery is what the fake server took in one conversation.
type delivery struct {
	from, to, data string
	secure, authed bool
}

// fakeServer speaks the part of SMTP that a sender uses. offerTLS adds STARTTLS; password makes it ask for AUTH PLAIN;
// rejectRecipient answers the RCPT command with a refusal that quotes the address, as real servers do.
type fakeServer struct {
	addr            string
	cert            *tls.Config
	offerTLS        bool
	user, password  string
	rejectRecipient bool
	silent          bool

	mu         sync.Mutex
	deliveries []delivery
	commands   []string
}

func selfSigned(t *testing.T) (*tls.Config, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "127.0.0.1"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}, pool
}

func startServer(t *testing.T, s *fakeServer) *fakeServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.addr = ln.Addr().String()
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(conn)
		}
	}()
	return s
}

func (s *fakeServer) serve(conn net.Conn) {
	defer conn.Close()
	if s.silent {
		time.Sleep(5 * time.Second)
		return
	}
	var secure, authed bool
	r := bufio.NewReader(conn)
	say := func(format string, a ...any) { fmt.Fprintf(conn, format+"\r\n", a...) }
	say("220 fake ESMTP")
	var d delivery
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		s.mu.Lock()
		s.commands = append(s.commands, strings.SplitN(line, " ", 2)[0])
		s.mu.Unlock()
		switch verb := strings.ToUpper(strings.SplitN(line, " ", 2)[0]); {
		case verb == "EHLO" || verb == "HELO":
			say("250-fake")
			if s.offerTLS && !secure {
				say("250-STARTTLS")
			}
			if s.password != "" {
				say("250-AUTH PLAIN")
			}
			say("250 8BITMIME")
		case verb == "STARTTLS":
			say("220 go ahead")
			tlsConn := tls.Server(conn, s.cert)
			if tlsConn.Handshake() != nil {
				return
			}
			conn, r, secure = tlsConn, bufio.NewReader(tlsConn), true
			say = func(format string, a ...any) { fmt.Fprintf(tlsConn, format+"\r\n", a...) }
		case verb == "AUTH":
			raw, _ := base64.StdEncoding.DecodeString(strings.Fields(line)[len(strings.Fields(line))-1])
			if string(raw) == "\x00"+s.user+"\x00"+s.password {
				authed = true
				say("235 ok")
			} else {
				say("535 bad credentials for %s", s.user)
			}
		case verb == "MAIL":
			if s.password != "" && !authed {
				say("530 authentication required")
				continue
			}
			d.from = line
			say("250 ok")
		case verb == "RCPT":
			if s.rejectRecipient {
				say("550 5.1.1 <%s>: Recipient address rejected: user unknown", strings.Trim(strings.SplitN(line, ":", 2)[1], "<> "))
				continue
			}
			d.to = line
			say("250 ok")
		case verb == "DATA":
			say("354 go")
			var body strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil || l == ".\r\n" {
					break
				}
				body.WriteString(l)
			}
			d.data, d.secure, d.authed = body.String(), secure, authed
			s.mu.Lock()
			s.deliveries = append(s.deliveries, d)
			s.mu.Unlock()
			say("250 queued")
		case verb == "QUIT":
			say("221 bye")
			return
		default:
			say("250 ok")
		}
	}
}

func (s *fakeServer) took() ([]delivery, []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]delivery(nil), s.deliveries...), append([]string(nil), s.commands...)
}

func config(s *fakeServer) smtpmail.Config {
	host, port, _ := net.SplitHostPort(s.addr)
	var p int
	fmt.Sscan(port, &p)
	return smtpmail.Config{Host: host, Port: p, From: "no-reply@multitour.example", PublicBaseURL: "https://app.multitour.example"}
}

func mustMailer(t *testing.T, c smtpmail.Config) *smtpmail.Mailer {
	t.Helper()
	m, err := smtpmail.New(c)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return m
}

func TestI_TheMessageReachesTheAddressOverPlainSmtpInDevelopment(t *testing.T) {
	s := startServer(t, &fakeServer{})
	if err := mustMailer(t, config(s)).SendVerification(ctx, verification()); err != nil {
		t.Fatal(err)
	}
	got, _ := s.took()
	if len(got) != 1 || !strings.Contains(got[0].from, "no-reply@multitour.example") || !strings.Contains(got[0].to, "ana@example.com") {
		t.Fatalf("deliveries = %+v", got)
	}
	if got[0].secure || !strings.Contains(got[0].data, "Subject:") || !strings.Contains(got[0].data, "verificar-correo#token=") {
		t.Fatalf("data = %q", got[0].data)
	}
}

func TestI_TlsIsUsedWhenTheServerOffersItAndRequiredWhenTheConfigurationSaysSo(t *testing.T) {
	tlsConfig, roots := selfSigned(t)
	s := startServer(t, &fakeServer{offerTLS: true, cert: tlsConfig})
	c := config(s)
	c.RequireTLS, c.TLSConfig = true, &tls.Config{RootCAs: roots}
	if err := mustMailer(t, c).SendVerification(ctx, verification()); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.took(); len(got) != 1 || !got[0].secure {
		t.Fatalf("deliveries = %+v, want one over TLS", got)
	}
}

func TestI_RequiredTlsRefusesAServerWithoutItAndSendsNothing(t *testing.T) {
	s := startServer(t, &fakeServer{})
	c := config(s)
	c.RequireTLS = true
	err := mustMailer(t, c).SendVerification(ctx, verification())
	if err == nil {
		t.Fatal("a server without STARTTLS was accepted although TLS is required")
	}
	got, commands := s.took()
	for _, command := range commands {
		if command == "MAIL" || command == "RCPT" || command == "DATA" || command == "AUTH" {
			t.Fatalf("the sender said %s to a server it could not trust with TLS", command)
		}
	}
	if len(got) != 0 {
		t.Fatal("the link travelled in clear")
	}
	if strings.Contains(err.Error(), token) {
		t.Fatal("the error carries the link")
	}
}

func TestI_TheCredentialsAreSentWithPlainAuthAndAWrongOneIsAnErrorThatDoesNotQuoteThePassword(t *testing.T) {
	s := startServer(t, &fakeServer{user: "mailer", password: "s3cret-Pass"})
	c := config(s)
	c.User, c.Password = "mailer", "s3cret-Pass"
	if err := mustMailer(t, c).SendVerification(ctx, verification()); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.took(); len(got) != 1 || !got[0].authed {
		t.Fatalf("deliveries = %+v, want one authenticated", got)
	}
	c.Password = "wrong-Pass"
	err := mustMailer(t, c).SendVerification(ctx, verification())
	if err == nil || strings.Contains(err.Error(), "wrong-Pass") || strings.Contains(err.Error(), "s3cret-Pass") {
		t.Fatalf("err = %v: a wrong credential is an error and the password is not in it", err)
	}
}

func TestI_ARefusedRecipientIsAnErrorThatQuotesNeitherTheAddressNorTheLink(t *testing.T) {
	s := startServer(t, &fakeServer{rejectRecipient: true})
	err := mustMailer(t, config(s)).SendVerification(ctx, verification())
	if err == nil {
		t.Fatal("a refused recipient was a success")
	}
	if strings.Contains(err.Error(), "ana@example.com") || strings.Contains(err.Error(), token) || !strings.Contains(err.Error(), "550") {
		t.Fatalf("err = %q: it must keep the code of the refusal and drop the address of the person", err)
	}
}

func TestI_ARefusedConnectionIsAnErrorThatNamesTheFailureNotTheLink(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := ln.Addr().String()
	_ = ln.Close()
	host, port, _ := net.SplitHostPort(closed)
	var p int
	fmt.Sscan(port, &p)
	err := mustMailer(t, smtpmail.Config{Host: host, Port: p, From: "no-reply@multitour.example", PublicBaseURL: "https://app.multitour.example"}).
		SendVerification(ctx, verification())
	if err == nil || strings.Contains(err.Error(), token) || strings.Contains(err.Error(), "ana@example.com") || !strings.HasPrefix(err.Error(), "smtp:") {
		t.Fatalf("err = %v", err)
	}
}

func TestI_AServerThatNeverAnswersEndsWithTheDeadlineOfTheCaller(t *testing.T) {
	s := startServer(t, &fakeServer{silent: true})
	limited, cancel := context.WithTimeout(ctx, 400*time.Millisecond)
	defer cancel()
	started := time.Now()
	if err := mustMailer(t, config(s)).SendVerification(limited, verification()); err == nil {
		t.Fatal("a silent server was a success")
	}
	if took := time.Since(started); took > 3*time.Second {
		t.Fatalf("it waited %s, the deadline was 400 ms", took)
	}
}
