package openvpn

import "testing"

func TestParseOCCOptions(t *testing.T) {
	opts := parseOCCOptions("V4,dev-type tun,link-mtu 1549,tun-mtu 1500,proto UDPv4,cipher AES-256-CBC,auth SHA512,keysize 256,key-method 2,tls-server")
	if opts["cipher"] != "AES-256-CBC" || opts["auth"] != "SHA512" || opts["dev-type"] != "tun" {
		t.Fatalf("parsed = %v", opts)
	}
	if v, ok := opts["V4"]; !ok || v != "" {
		t.Fatalf("valueless field: %q ok=%v", v, ok)
	}
	if _, ok := opts["missing"]; ok {
		t.Fatal("unexpected key")
	}
}

func TestEffectiveAuthFollowsServerForCBC(t *testing.T) {
	client := &Client{config: &ClientConfig{Cipher: CipherAES256CBC, Auth: AuthSHA1}}

	client.adoptServerOptions("V4,dev-type tun,cipher AES-256-CBC,auth SHA256,keysize 256,key-method 2,tls-server")
	if client.serverAuth != AuthSHA256 {
		t.Fatalf("serverAuth = %q, want SHA256", client.serverAuth)
	}
	if got := client.effectiveAuth(CipherAES256CBC); got != AuthSHA256 {
		t.Fatalf("CBC effective auth = %q, want server's SHA256", got)
	}
	if got := client.effectiveAuth(CipherAES128GCM); got != AuthSHA1 {
		t.Fatalf("AEAD effective auth = %q, want configured SHA1", got)
	}

	client = &Client{config: &ClientConfig{Cipher: CipherAES256CBC, Auth: AuthSHA1}}
	client.adoptServerOptions("V4,dev-type tun,cipher AES-256-CBC,auth [null-digest],keysize 256")
	if client.serverAuth != "" || client.effectiveAuth(CipherAES256CBC) != AuthSHA1 {
		t.Fatalf("unsupported server auth must keep the configured digest, got %q", client.serverAuth)
	}

	client = &Client{config: &ClientConfig{Cipher: CipherAES256CBC, Auth: AuthSHA1}}
	client.adoptServerOptions("V4,dev-type tun,cipher AES-256-CBC,auth SHA-1,keysize 256")
	if client.effectiveAuth(CipherAES256CBC) != AuthSHA1 {
		t.Fatal("SHA-1 spelling must normalize to SHA1")
	}

	client = &Client{config: &ClientConfig{Cipher: CipherAES256CBC, Auth: AuthSHA1}}
	client.adoptServerOptions("V4,dev-type tun,cipher AES-256-CBC")
	if client.serverAuth != "" {
		t.Fatal("missing auth must not set serverAuth")
	}
}
