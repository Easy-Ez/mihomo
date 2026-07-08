package openvpn

import "testing"

func TestEffectiveAuthAdoptsServerAuthForCBC(t *testing.T) {
	c := &Client{config: &ClientConfig{Cipher: CipherAES256CBC, Auth: AuthSHA256}}

	// No server auth known yet: fall back to the configured digest.
	if got := c.effectiveAuth(CipherAES256CBC); got != AuthSHA256 {
		t.Fatalf("expected configured auth, got %q", got)
	}

	// Server declares SHA1 (OpenVPN's default when --auth is omitted). A CBC
	// data channel must adopt it, or its HMAC would never verify.
	c.adoptServerOptions("V4,dev-type tun,cipher AES-256-CBC,auth SHA1,keysize 256,key-method 2,tls-server")
	if c.serverAuth != AuthSHA1 {
		t.Fatalf("expected serverAuth SHA1, got %q", c.serverAuth)
	}
	if got := c.effectiveAuth(CipherAES256CBC); got != AuthSHA1 {
		t.Fatalf("CBC should adopt server auth SHA1, got %q", got)
	}
}

func TestEffectiveAuthIgnoredForAEAD(t *testing.T) {
	c := &Client{config: &ClientConfig{Cipher: CipherAES128GCM, Auth: AuthSHA256}}
	// AEAD server advertises [null-digest]; it must not be adopted, and the
	// AEAD data channel ignores auth anyway.
	c.adoptServerOptions("V4,dev-type tun,cipher AES-128-GCM,auth [null-digest],keysize 128,key-method 2,tls-server")
	if c.serverAuth != "" {
		t.Fatalf("null-digest must not be adopted, got %q", c.serverAuth)
	}
	if got := c.effectiveAuth(CipherAES128GCM); got != AuthSHA256 {
		t.Fatalf("AEAD keeps configured auth, got %q", got)
	}
}

func TestAdoptServerOptionsIgnoresUnsupportedAuth(t *testing.T) {
	c := &Client{config: &ClientConfig{Cipher: CipherAES256CBC, Auth: AuthSHA256}}
	c.adoptServerOptions("V4,cipher AES-256-CBC,auth RSA-SHA9000,key-method 2")
	if c.serverAuth != "" {
		t.Fatalf("unsupported auth must be ignored, got %q", c.serverAuth)
	}
}
