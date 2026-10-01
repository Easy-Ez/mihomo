package openvpn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

func newTestServerCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:      []string{"KG"},
			Province:     []string{"NA"},
			Locality:     []string{"Bishkek"},
			Organization: []string{"OpenVPN-TEST"},
			CommonName:   "Server-1",
			ExtraNames: []pkix.AttributeTypeAndValue{{
				Type:  asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1},
				Value: "me@myhost.mydomain",
			}},
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestVerifyX509Name(t *testing.T) {
	cert := newTestServerCert(t)
	cases := []struct {
		name, nameType string
		wantErr        bool
	}{
		{"Server-1", "", false},
		{"Server-1", VerifyX509TypeName, false},
		{"Server-2", VerifyX509TypeName, true},
		{"server-1", VerifyX509TypeName, true},
		{"Server", VerifyX509TypeNamePrefix, false},
		{"Server-1", VerifyX509TypeNamePrefix, false},
		{"Client", VerifyX509TypeNamePrefix, true},
		{"C=KG, ST=NA, L=Bishkek, O=OpenVPN-TEST, CN=Server-1, emailAddress=me@myhost.mydomain", VerifyX509TypeSubject, false},
		{"CN=Server-1", VerifyX509TypeSubject, true},
		{"Server-1", "bogus", true},
	}
	for _, tc := range cases {
		err := verifyX509Name(cert, tc.name, tc.nameType)
		if (err != nil) != tc.wantErr {
			t.Errorf("verifyX509Name(%q, %q) error = %v, wantErr %v", tc.name, tc.nameType, err, tc.wantErr)
		}
	}
}

func TestX509SubjectStringKeepsCertificateOrder(t *testing.T) {
	cert := newTestServerCert(t)
	got := x509SubjectString(cert.Subject)
	want := "C=KG, ST=NA, L=Bishkek, O=OpenVPN-TEST, CN=Server-1, emailAddress=me@myhost.mydomain"
	if got != want {
		t.Fatalf("subject = %q, want %q", got, want)
	}
}

func TestConfigVerifyX509NameType(t *testing.T) {
	base := func() *ClientConfig {
		return &ClientConfig{
			RemoteHost: "vpn.example.com",
			RemotePort: 1194,
			CA:         []byte(testCert),
			Username:   "user",
		}
	}
	cfg := base()
	if err := cfg.Prepare(); err != nil {
		t.Fatal(err)
	}
	if cfg.VerifyX509NameType != VerifyX509TypeName {
		t.Fatalf("default type = %q, want %q", cfg.VerifyX509NameType, VerifyX509TypeName)
	}

	cfg = base()
	cfg.VerifyX509Name = " Server-1 "
	cfg.VerifyX509NameType = "Name-Prefix"
	if err := cfg.Prepare(); err != nil {
		t.Fatal(err)
	}
	if cfg.VerifyX509Name != "Server-1" || cfg.VerifyX509NameType != VerifyX509TypeNamePrefix {
		t.Fatalf("normalized = %q/%q", cfg.VerifyX509Name, cfg.VerifyX509NameType)
	}

	cfg = base()
	cfg.VerifyX509NameType = "dns"
	if err := cfg.Prepare(); err == nil {
		t.Fatal("unsupported verify-x509-name-type must be rejected")
	}
}
