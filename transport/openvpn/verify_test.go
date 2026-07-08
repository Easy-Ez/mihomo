package openvpn

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
)

func TestVerifyX509Name(t *testing.T) {
	cert := &x509.Certificate{Subject: pkix.Name{CommonName: "server.example.com"}}

	cases := []struct {
		name     string
		nameType string
		want     string
		ok       bool
	}{
		{"name exact match", VerifyX509TypeName, "server.example.com", true},
		{"name default type match", "", "server.example.com", true},
		{"name mismatch", VerifyX509TypeName, "other.example.com", false},
		{"prefix match", VerifyX509TypeNamePrefix, "server.", true},
		{"prefix mismatch", VerifyX509TypeNamePrefix, "client.", false},
		{"unknown type", "weird", "server.example.com", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := verifyX509Name(cert, tc.want, tc.nameType)
			if tc.ok && err != nil {
				t.Fatalf("expected pass, got %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("expected failure, got nil")
			}
		})
	}
}

func TestVerifyX509NameSubject(t *testing.T) {
	cert := &x509.Certificate{Subject: pkix.Name{CommonName: "server", Organization: []string{"mihomo"}}}
	subject := cert.Subject.String()
	if err := verifyX509Name(cert, subject, VerifyX509TypeSubject); err != nil {
		t.Fatalf("subject exact match should pass: %v", err)
	}
	if err := verifyX509Name(cert, "CN=nope", VerifyX509TypeSubject); err == nil {
		t.Fatal("subject mismatch should fail")
	}
}

func TestConfigValidatesVerifyX509NameType(t *testing.T) {
	cfg := yamlStyleConfig()
	cfg.VerifyX509Name = "server.example.com"
	cfg.VerifyX509NameType = "bogus"
	if err := cfg.Prepare(); err == nil {
		t.Fatal("expected invalid verify-x509-name type error")
	}

	cfg = yamlStyleConfig()
	cfg.VerifyX509Name = "server.example.com"
	if err := cfg.Prepare(); err != nil {
		t.Fatal(err)
	}
	if cfg.VerifyX509NameType != VerifyX509TypeName {
		t.Fatalf("expected default type %q, got %q", VerifyX509TypeName, cfg.VerifyX509NameType)
	}
}
