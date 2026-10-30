package dbrijsecrets

// Dbrij Secrets' cryptography for machines, matching the Node SDK, the Python SDK and the
// dashboard byte for byte:
//
//   - A value is AES-256-GCM sealed under its environment key, bound by associated data to
//     its environment, folder, name and owner.
//   - The environment key reaches a machine RSA-OAEP (SHA-256) wrapped to the public key of
//     the machine credential.
//   - The credential's private key is sealed under HKDF-SHA256(key secret), and the key
//     secret lives only in the token on the machine.
//
// Dbrij holds every input here except the key secret.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const (
	tokenPrefix = "dbs_"
	keyPrefix   = "dbsk_"
	machineInfo = "dbrij-secrets-machine-v1"
	b32Alphabet = "0123456789abcdefghjkmnpqrstvwxyz"
)

// base32 is lowercase Crockford base32, as the tokens are written.
func base32(data []byte) string {
	var bits, value uint32
	var out strings.Builder
	for _, b := range data {
		value = value<<8 | uint32(b)
		bits += 8
		for bits >= 5 {
			out.WriteByte(b32Alphabet[(value>>(bits-5))&31])
			bits -= 5
		}
	}
	if bits > 0 {
		out.WriteByte(b32Alphabet[(value<<(5-bits))&31])
	}
	return out.String()
}

func unbase32(text string) ([]byte, bool) {
	var bits, value uint32
	out := make([]byte, 0, len(text)*5/8)
	for i := 0; i < len(text); i++ {
		idx := strings.IndexByte(b32Alphabet, text[i])
		if idx < 0 {
			return nil, false
		}
		value = value<<5 | uint32(idx)
		bits += 5
		if bits >= 8 {
			out = append(out, byte(value>>(bits-8)))
			bits -= 8
		}
	}
	return out, true
}

// Token is a parsed machine token (dbs_...) or login key (dbsk_...).
type Token struct {
	// Kind is "token" for a machine token, "key" for a login key.
	Kind string
	// CredentialHex is the credential id as 32 hex characters.
	CredentialHex string
	// CredentialID is the credential id as a uuid.
	CredentialID string
	authSecret   string
	keySecret    []byte
}

// Bearer is what is sent to Dbrij: the first two parts only. The key half never leaves.
func (t *Token) Bearer() (string, error) {
	if t.authSecret == "" {
		return "", errors.New("a key alone cannot sign in; it logs in with its platform's identity")
	}
	return tokenPrefix + t.CredentialHex + "_" + t.authSecret, nil
}

func checkOf(body string) string {
	sum := sha256.Sum256([]byte(body))
	return base32(sum[:])[:6]
}

func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// ParseToken reads a machine token or login key, or says what is wrong with it.
func ParseToken(text string) (*Token, error) {
	text = strings.TrimSpace(text)
	isKey := strings.HasPrefix(text, keyPrefix)
	if !isKey && !strings.HasPrefix(text, tokenPrefix) {
		return nil, errors.New("that is not a Dbrij Secrets token. Tokens start with dbs_ (or dbsk_ for a login key)")
	}
	prefix, want := tokenPrefix, 4
	if isKey {
		prefix, want = keyPrefix, 3
	}
	parts := strings.Split(text[len(prefix):], "_")
	if len(parts) != want {
		if len(parts) == 1 && !isKey {
			return nil, errors.New("that token is missing its key half. Copy the whole token again")
		}
		return nil, errors.New("that token is incomplete. Copy the whole token again")
	}
	hex, check := parts[0], parts[len(parts)-1]
	body := text[:len(text)-len(check)-1]
	cutShort := errors.New("that token was cut short or changed. Copy the whole token again")
	if len(hex) != 32 || !isLowerHex(hex) || check != checkOf(body) {
		return nil, cutShort
	}
	key, ok := unbase32(parts[len(parts)-2])
	if !ok || len(key) < 32 {
		return nil, cutShort
	}
	t := &Token{
		Kind:          "token",
		CredentialHex: hex,
		CredentialID:  hex[0:8] + "-" + hex[8:12] + "-" + hex[12:16] + "-" + hex[16:20] + "-" + hex[20:],
		keySecret:     key[:32],
	}
	if isKey {
		t.Kind = "key"
	} else {
		t.authSecret = parts[1]
	}
	return t, nil
}

// formatKey writes a login key for a credential and key secret, as the dashboard does.
func formatKey(credentialHex string, keySecret []byte) string {
	body := keyPrefix + credentialHex + "_" + base32(keySecret)
	return body + "_" + checkOf(body)
}

func openMachinePrivateKey(keySecret []byte, keySalt, encryptedPrivateKey string) (*rsa.PrivateKey, error) {
	wrong := errors.New("the token does not open this machine's key. Is it the whole token, from this machine?")
	salt, err := base64.StdEncoding.DecodeString(keySalt)
	if err != nil {
		return nil, wrong
	}
	kek, err := hkdf.Key(sha256.New, keySecret, salt, machineInfo, 32)
	if err != nil {
		return nil, err
	}
	blob, err := base64.StdEncoding.DecodeString(encryptedPrivateKey)
	if err != nil || len(blob) < 12+16 {
		return nil, wrong
	}
	gcm, err := newGCM(kek)
	if err != nil {
		return nil, err
	}
	pkcs8, err := gcm.Open(nil, blob[:12], blob[12:], nil)
	if err != nil {
		return nil, wrong
	}
	parsed, err := x509.ParsePKCS8PrivateKey(pkcs8)
	if err != nil {
		return nil, fmt.Errorf("the machine key did not read: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("the machine key is not an RSA key")
	}
	return key, nil
}

// unwrapEnvironmentKey opens an environment key wrapped RSA-OAEP with SHA-256 (and MGF1
// with SHA-256, which is what WebCrypto and Go both use for one hash).
func unwrapEnvironmentKey(wrapped string, key *rsa.PrivateKey) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(wrapped)
	if err != nil {
		return nil, err
	}
	return rsa.DecryptOAEP(sha256.New(), nil, key, data, nil)
}

func secretsAAD(environmentID string, folderID *string, key string, ownerUserID *string) []byte {
	folder, owner := "root", "shared"
	if folderID != nil && *folderID != "" {
		folder = *folderID
	}
	if ownerUserID != nil && *ownerUserID != "" {
		owner = *ownerUserID
	}
	return []byte("dbrij-secrets:v1|" + environmentID + "|" + folder + "|" + key + "|" + owner)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// sealedPayload is what a value holds once opened: the value, and an optional note.
type sealedPayload struct {
	V string `json:"v"`
	N string `json:"n,omitempty"`
}

// openValue opens a value, or reports false when it does not belong to that place or key.
func openValue(envKey, aad []byte, ciphertext, iv string) (sealedPayload, bool) {
	data, err1 := base64.StdEncoding.DecodeString(ciphertext)
	nonce, err2 := base64.StdEncoding.DecodeString(iv)
	if err1 != nil || err2 != nil || len(nonce) != 12 {
		return sealedPayload{}, false
	}
	gcm, err := newGCM(envKey)
	if err != nil {
		return sealedPayload{}, false
	}
	plain, err := gcm.Open(nil, nonce, data, aad)
	if err != nil {
		return sealedPayload{}, false
	}
	var raw map[string]any
	if json.Unmarshal(plain, &raw) != nil {
		return sealedPayload{}, false
	}
	v, ok := raw["v"].(string)
	if !ok {
		return sealedPayload{}, false
	}
	n, _ := raw["n"].(string)
	return sealedPayload{V: v, N: n}, true
}

// sealValue seals a value (and note) to its place under the environment key.
func sealValue(envKey, aad []byte, value, note string) (ciphertext, iv string, err error) {
	var body bytes.Buffer
	enc := json.NewEncoder(&body)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(sealedPayload{V: value, N: note}); err != nil {
		return "", "", err
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return "", "", err
	}
	gcm, err := newGCM(envKey)
	if err != nil {
		return "", "", err
	}
	sealed := gcm.Seal(nil, nonce, bytes.TrimRight(body.Bytes(), "\n"), aad)
	return base64.StdEncoding.EncodeToString(sealed), base64.StdEncoding.EncodeToString(nonce), nil
}
