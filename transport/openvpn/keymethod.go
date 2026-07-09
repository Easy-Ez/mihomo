package openvpn

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"sort"
	"strings"
)

const (
	KeyMethod2 = 2

	keySourcePreMasterSize = 48
	keySourceRandomSize    = 32

	maxCipherKeyLength = 64
	maxHMACKeyLength   = 64
	keyBlockSize       = 2 * (maxCipherKeyLength + maxHMACKeyLength)

	keyExpansionID = "OpenVPN"
)

type KeySource struct {
	PreMaster [keySourcePreMasterSize]byte
	Random1   [keySourceRandomSize]byte
	Random2   [keySourceRandomSize]byte
}

type KeySource2 struct {
	Client KeySource
	Server KeySource
}

type KeyMaterial struct {
	SendCipherKey []byte
	SendHMACKey   []byte
	RecvCipherKey []byte
	RecvHMACKey   []byte
}

type KeyMethod2Record struct {
	Sources  KeySource2
	Options  string
	Username string
	Password string
	PeerInfo string
}

func NewClientKeyMethod2Record(options, peerInfo, username, password string) (*KeyMethod2Record, error) {
	var record KeyMethod2Record
	if _, err := rand.Read(record.Sources.Client.PreMaster[:]); err != nil {
		return nil, err
	}
	if _, err := rand.Read(record.Sources.Client.Random1[:]); err != nil {
		return nil, err
	}
	if _, err := rand.Read(record.Sources.Client.Random2[:]); err != nil {
		return nil, err
	}
	record.Options = options
	record.PeerInfo = peerInfo
	record.Username = username
	record.Password = password
	return &record, nil
}

func (r *KeyMethod2Record) MarshalClient() ([]byte, error) {
	if r == nil {
		return nil, errors.New("nil key method 2 record")
	}
	out := make([]byte, 0, 4+1+keySourcePreMasterSize+keySourceRandomSize*2+len(r.Options)+16)
	out = binary.BigEndian.AppendUint32(out, 0)
	out = append(out, KeyMethod2)
	out = append(out, r.Sources.Client.PreMaster[:]...)
	out = append(out, r.Sources.Client.Random1[:]...)
	out = append(out, r.Sources.Client.Random2[:]...)
	out = appendOpenVPNString(out, r.Options)
	out = appendOpenVPNString(out, r.Username)
	out = appendOpenVPNString(out, r.Password)
	out = appendOpenVPNString(out, r.PeerInfo)
	return out, nil
}

func ParseServerKeyMethod2Record(packet []byte) (*KeyMethod2Record, error) {
	record, _, err := parseServerKeyMethod2Record(packet)
	return record, err
}

// parseServerKeyMethod2Record also returns how many bytes of packet the
// record occupies, so callers can preserve trailing data (the server may
// coalesce its key method record with e.g. a PUSH_REPLY in one TLS flight).
func parseServerKeyMethod2Record(packet []byte) (*KeyMethod2Record, int, error) {
	if len(packet) < 4+1+keySourceRandomSize*2 {
		return nil, 0, fmt.Errorf("key method 2 packet too short: %w", ioStringEOF)
	}
	if binary.BigEndian.Uint32(packet[:4]) != 0 {
		return nil, 0, errors.New("invalid key method 2 prefix")
	}
	if packet[4]&0x0f != KeyMethod2 {
		return nil, 0, fmt.Errorf("unsupported key method %d", packet[4])
	}
	offset := 5
	record := &KeyMethod2Record{}
	copy(record.Sources.Server.Random1[:], packet[offset:offset+keySourceRandomSize])
	offset += keySourceRandomSize
	copy(record.Sources.Server.Random2[:], packet[offset:offset+keySourceRandomSize])
	offset += keySourceRandomSize

	var err error
	record.Options, offset, err = readOpenVPNString(packet, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("read options: %w", err)
	}
	// A server record normally ends after the options string; the remaining
	// strings are only written by clients. Read them leniently and stop at
	// the first field that is absent.
	if username, next, err := readOpenVPNString(packet, offset); err == nil {
		record.Username, offset = username, next
		if password, next, err := readOpenVPNString(packet, offset); err == nil {
			record.Password, offset = password, next
			if peerInfo, next, err := readOpenVPNString(packet, offset); err == nil {
				record.PeerInfo, offset = peerInfo, next
			}
		}
	}
	return record, offset, nil
}

func DeriveClientKeyMaterial(sources KeySource2, clientSession, serverSession SessionID, cipherKeyLen int) (*KeyMaterial, error) {
	if cipherKeyLen != 16 && cipherKeyLen != 24 && cipherKeyLen != 32 {
		return nil, fmt.Errorf("unsupported data cipher key length %d", cipherKeyLen)
	}
	var master [48]byte
	if err := openvpnPRF(
		sources.Client.PreMaster[:],
		keyExpansionID+" master secret",
		sources.Client.Random1[:],
		sources.Server.Random1[:],
		nil,
		nil,
		master[:],
	); err != nil {
		return nil, err
	}

	keyBlock := make([]byte, keyBlockSize)
	if err := openvpnPRF(
		master[:],
		keyExpansionID+" key expansion",
		sources.Client.Random2[:],
		sources.Server.Random2[:],
		clientSession[:],
		serverSession[:],
		keyBlock,
	); err != nil {
		return nil, err
	}

	clientToServer := keyBlock[:maxCipherKeyLength+maxHMACKeyLength]
	serverToClient := keyBlock[maxCipherKeyLength+maxHMACKeyLength:]
	return &KeyMaterial{
		SendCipherKey: cloneBytes(clientToServer[:cipherKeyLen]),
		SendHMACKey:   cloneBytes(clientToServer[maxCipherKeyLength : maxCipherKeyLength+maxHMACKeyLength]),
		RecvCipherKey: cloneBytes(serverToClient[:cipherKeyLen]),
		RecvHMACKey:   cloneBytes(serverToClient[maxCipherKeyLength : maxCipherKeyLength+maxHMACKeyLength]),
	}, nil
}

func installScriptOptionsString(proto, cipher, auth string, mode compressionMode, tunMTU int) string {
	protoName := "UDPv4"
	if proto == ProtoTCP {
		protoName = "TCPv4_CLIENT"
	}
	keysize := "128"
	if cipher == CipherAES256GCM || cipher == CipherAES256CBC || cipher == CipherChaCha20Poly1305 {
		keysize = "256"
	}
	if tunMTU <= 0 {
		tunMTU = 1500
	}
	mtuInt := tunMTU + 50
	comp := ""
	if mode == compressLZO {
		mtuInt = tunMTU + 44
		comp = "comp-lzo,"
	}
	mtu := fmt.Sprintf("%d", mtuInt)
	return fmt.Sprintf("V4,dev-type tun,link-mtu %s,tun-mtu %d,proto %s,%scipher %s,auth %s,keysize %s,key-method 2,tls-client", mtu, tunMTU, protoName, comp, cipher, auth, keysize)
}

func installScriptPeerInfo(cipher string, mode compressionMode, peerInfo map[string]string) string {
	comp := ""
	switch mode {
	case compressLZO:
		comp = "IV_LZO=1\n"
	case compressV1Stub:
		comp = "IV_COMP_STUB=1\nIV_LZO_STUB=1\n"
	case compressV2Stub:
		comp = "IV_COMP_STUBv2=1\nIV_COMP_STUB=1\nIV_LZO_STUB=1\n"
	}
	
	// The server's strict DPI firewall relies on the exact ordering of the initial core variables.
	// We must hardcode the standard official client order to bypass the fingerprinting.
	info := fmt.Sprintf("IV_VER=3.8.4\nIV_PLAT=mac\nIV_PROTO=2\nIV_NCP=2\nIV_TCPNL=1\nIV_LZO=1\nIV_COMP_STUBv2=1\nIV_COMP_STUB=1\n%sIV_CIPHERS=%s\n", comp, dataCiphersList(cipher))

	// Append user-defined peer-info entries (e.g. IV_HWADDR, UV_*) after the
	// built-in fields. Keys are sorted so the output is deterministic.
	keys := make([]string, 0, len(peerInfo))
	for key := range peerInfo {
		// Filter out the ones we hardcoded to prevent duplicates
		if key == "IV_VER" || key == "IV_PLAT" || key == "IV_PROTO" || key == "IV_NCP" || key == "IV_TCPNL" || key == "IV_LZO" || key == "IV_COMP_STUBv2" || key == "IV_COMP_STUB" {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		info += fmt.Sprintf("%s=%s\n", key, peerInfo[key])
	}
	return info
}

// dataCiphersList builds the IV_CIPHERS advertisement: the configured
// cipher first (so a server honoring order prefers it) followed by the
// common AEAD ciphers this client can also run. Advertising several lets
// the server pick via NCP; the choice is applied from the pushed "cipher".
func dataCiphersList(cipher string) string {
	ciphers := []string{cipher}
	for _, candidate := range []string{CipherAES256GCM, CipherAES128GCM, CipherChaCha20Poly1305} {
		if candidate != cipher {
			ciphers = append(ciphers, candidate)
		}
	}
	return strings.Join(ciphers, ":")
}

func appendOpenVPNString(out []byte, s string) []byte {
	if s == "" {
		return binary.BigEndian.AppendUint16(out, 0)
	}
	if len(s)+1 > 0xffff {
		s = s[:0xfffe]
	}
	out = binary.BigEndian.AppendUint16(out, uint16(len(s)+1))
	out = append(out, s...)
	out = append(out, 0)
	return out
}

func readOpenVPNString(packet []byte, offset int) (string, int, error) {
	if offset+2 > len(packet) {
		return "", offset, ioStringEOF
	}
	size := int(binary.BigEndian.Uint16(packet[offset : offset+2]))
	offset += 2
	if size == 0 {
		return "", offset, nil
	}
	if offset+size > len(packet) {
		return "", offset, ioStringEOF
	}
	raw := packet[offset : offset+size]
	offset += size
	if raw[len(raw)-1] == 0 {
		raw = raw[:len(raw)-1]
	}
	return string(raw), offset, nil
}

var ioStringEOF = errors.New("openvpn string truncated")

func openvpnPRF(secret []byte, label string, clientSeed, serverSeed, clientSession, serverSession []byte, out []byte) error {
	seed := make([]byte, 0, len(label)+len(clientSeed)+len(serverSeed)+len(clientSession)+len(serverSession))
	seed = append(seed, label...)
	seed = append(seed, clientSeed...)
	seed = append(seed, serverSeed...)
	seed = append(seed, clientSession...)
	seed = append(seed, serverSession...)

	split := (len(secret) + 1) / 2
	s1 := secret[:split]
	s2 := secret[len(secret)-split:]

	md5Out := pHash(md5.New, s1, seed, len(out))
	sha1Out := pHash(sha1.New, s2, seed, len(out))
	for i := range out {
		out[i] = md5Out[i] ^ sha1Out[i]
	}
	return nil
}

func pHash(newHash func() hash.Hash, secret, seed []byte, size int) []byte {
	out := make([]byte, 0, size)
	a := hmacSum(newHash, secret, seed)
	for len(out) < size {
		chunkInput := make([]byte, 0, len(a)+len(seed))
		chunkInput = append(chunkInput, a...)
		chunkInput = append(chunkInput, seed...)
		out = append(out, hmacSum(newHash, secret, chunkInput)...)
		a = hmacSum(newHash, secret, a)
	}
	return out[:size]
}

func hmacSum(newHash func() hash.Hash, key, data []byte) []byte {
	mac := hmac.New(newHash, key)
	_, _ = mac.Write(data)
	return mac.Sum(nil)
}
