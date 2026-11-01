package dbrijsecrets

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
)

// Key management from Go, with the same machine token:
//
//	ct, err := client.Keys().Encrypt(ctx, keyID, []byte("a customer BVN"), map[string]string{"table": "customers"})
//	bvn, err := client.Keys().Decrypt(ctx, keyID, ct.Ciphertext, map[string]string{"table": "customers"})
//
// The key never leaves Dbrij: data (up to 4 KB) goes to it and comes back encrypted or
// decrypted. EncryptLarge asks for a data key, encrypts here with it (AES 256 GCM) and keeps
// only the data key's encrypted copy, in the envelope format every Dbrij SDK shares (pinned
// by testdata/kms-fixture.json, written by the Node SDK).

const envelopePrefix = "dkenv1"

// Keys uses Key management keys this machine was granted.
type Keys struct{ c *Client }

// Keys returns the Key management side of the client.
func (c *Client) Keys() *Keys { return &Keys{c: c} }

// CiphertextResult is a ciphertext and the key version that made it.
type CiphertextResult struct {
	Ciphertext string `json:"ciphertext"`
	KeyVersion int    `json:"keyVersion"`
}

// DataKey is a fresh data key: use Plaintext here and drop it; keep Ciphertext.
type DataKey struct {
	Plaintext  []byte
	Ciphertext string
	KeyVersion int
}

// SignatureResult is a signature (base64) and the version that made it.
type SignatureResult struct {
	Signature  string `json:"signature"`
	KeyVersion int    `json:"keyVersion"`
}

// MacResult is a MAC (base64) and the version that made it.
type MacResult struct {
	Mac        string `json:"mac"`
	KeyVersion int    `json:"keyVersion"`
}

// PublicKey is the public half of an asymmetric or signing key.
type PublicKey struct {
	KeyVersion   int    `json:"keyVersion"`
	Algorithm    string `json:"algorithm"`
	PublicKeyPem string `json:"publicKeyPem"`
}

func (k *Keys) call(ctx context.Context, method, keyID, op string, body any, out any) error {
	_, raw, err := k.c.request(ctx, method, "/secrets/machine/kms/keys/"+url.PathEscape(keyID)+"/"+op, body, nil, true)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// withContext adds the context to a body only when there is one, as the Node SDK leaves it out.
func withContext(body map[string]any, context map[string]string) map[string]any {
	if len(context) > 0 {
		body["context"] = context
	}
	return body
}

// Encrypt sends data (up to 4 KB) and gets it back encrypted, bound to the context.
func (k *Keys) Encrypt(ctx context.Context, keyID string, data []byte, context map[string]string) (*CiphertextResult, error) {
	var r CiphertextResult
	err := k.call(ctx, "POST", keyID, "encrypt", withContext(map[string]any{"plaintext": b64(data)}, context), &r)
	return &r, err
}

// Decrypt needs the same context the value was encrypted with.
func (k *Keys) Decrypt(ctx context.Context, keyID, ciphertext string, context map[string]string) ([]byte, error) {
	var r struct {
		Plaintext string `json:"plaintext"`
	}
	if err := k.call(ctx, "POST", keyID, "decrypt", withContext(map[string]any{"ciphertext": ciphertext}, context), &r); err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(r.Plaintext)
}

// NewDataKey asks for a data key of 16, 24 or 32 bytes.
func (k *Keys) NewDataKey(ctx context.Context, keyID string, size int, context map[string]string) (*DataKey, error) {
	var r struct {
		Plaintext  string `json:"plaintext"`
		Ciphertext string `json:"ciphertext"`
		KeyVersion int    `json:"keyVersion"`
	}
	if err := k.call(ctx, "POST", keyID, "data-key", withContext(map[string]any{"bytes": size}, context), &r); err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(r.Plaintext)
	if err != nil {
		return nil, err
	}
	return &DataKey{Plaintext: raw, Ciphertext: r.Ciphertext, KeyVersion: r.KeyVersion}, nil
}

// Reencrypt moves a ciphertext to the key's newest version; the plaintext never comes back.
func (k *Keys) Reencrypt(ctx context.Context, keyID, ciphertext string, context map[string]string) (*CiphertextResult, error) {
	var r CiphertextResult
	err := k.call(ctx, "POST", keyID, "reencrypt", withContext(map[string]any{"ciphertext": ciphertext}, context), &r)
	return &r, err
}

// Sign signs data with a signing key.
func (k *Keys) Sign(ctx context.Context, keyID string, data []byte) (*SignatureResult, error) {
	var r SignatureResult
	err := k.call(ctx, "POST", keyID, "sign", map[string]any{"message": b64(data)}, &r)
	return &r, err
}

// Verify checks a signature; keyVersion 0 tries every version, newest first.
func (k *Keys) Verify(ctx context.Context, keyID string, data []byte, signature string, keyVersion int) (bool, error) {
	body := map[string]any{"message": b64(data), "signature": signature}
	if keyVersion > 0 {
		body["keyVersion"] = keyVersion
	}
	var r struct {
		Valid bool `json:"valid"`
	}
	err := k.call(ctx, "POST", keyID, "verify", body, &r)
	return r.Valid, err
}

// Mac makes a MAC of data.
func (k *Keys) Mac(ctx context.Context, keyID string, data []byte) (*MacResult, error) {
	var r MacResult
	err := k.call(ctx, "POST", keyID, "mac", map[string]any{"message": b64(data)}, &r)
	return &r, err
}

// VerifyMac checks a MAC; keyVersion 0 tries every version.
func (k *Keys) VerifyMac(ctx context.Context, keyID string, data []byte, mac string, keyVersion int) (bool, error) {
	body := map[string]any{"message": b64(data), "mac": mac}
	if keyVersion > 0 {
		body["keyVersion"] = keyVersion
	}
	var r struct {
		Valid bool `json:"valid"`
	}
	err := k.call(ctx, "POST", keyID, "verify-mac", body, &r)
	return r.Valid, err
}

// PublicKey returns the current version's public half.
func (k *Keys) PublicKey(ctx context.Context, keyID string) (*PublicKey, error) {
	var r PublicKey
	err := k.call(ctx, "GET", keyID, "public-key", nil, &r)
	return &r, err
}

// EncryptLarge encrypts data of any size with a fresh data key, as one envelope string.
func (k *Keys) EncryptLarge(ctx context.Context, keyID string, data []byte, context map[string]string) (string, error) {
	dk, err := k.NewDataKey(ctx, keyID, 32, context)
	if err != nil {
		return "", err
	}
	defer clear(dk.Plaintext)
	iv := make([]byte, 12)
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}
	return SealEnvelope(dk.Plaintext, dk.Ciphertext, iv, data, context)
}

// DecryptLarge opens an envelope: Dbrij opens its data key, the data is opened here.
func (k *Keys) DecryptLarge(ctx context.Context, keyID, envelope string, context map[string]string) ([]byte, error) {
	dkCiphertext, body, err := ParseEnvelope(envelope)
	if err != nil {
		return nil, err
	}
	dataKey, err := k.Decrypt(ctx, keyID, dkCiphertext, context)
	if err != nil {
		return nil, err
	}
	defer clear(dataKey)
	return OpenEnvelope(dataKey, body, context)
}

// CanonicalKmsContext is the context as one stable string, exactly as Dbrij reads it.
func CanonicalKmsContext(context map[string]string) string {
	if len(context) == 0 {
		return ""
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	// As JavaScript writes it: no HTML escaping, and maps come out with their names sorted.
	enc.SetEscapeHTML(false)
	_ = enc.Encode(context)
	return strings.TrimSuffix(buf.String(), "\n")
}

func gcm(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// SealEnvelope writes `dkenv1.<data key ciphertext>.<iv, data and tag>` (base64url parts).
func SealEnvelope(dataKey []byte, dataKeyCiphertext string, iv, data []byte, context map[string]string) (string, error) {
	aead, err := gcm(dataKey)
	if err != nil {
		return "", err
	}
	body := append(append([]byte{}, iv...), aead.Seal(nil, iv, data, []byte(envelopePrefix+"|"+CanonicalKmsContext(context)))...)
	return envelopePrefix + "." + b64url([]byte(dataKeyCiphertext)) + "." + b64url(body), nil
}

// ParseEnvelope splits an envelope into the data key's ciphertext and the sealed body.
func ParseEnvelope(envelope string) (string, []byte, error) {
	parts := strings.Split(envelope, ".")
	if len(parts) != 3 || parts[0] != envelopePrefix {
		return "", nil, errors.New("that is not a Dbrij envelope (dkenv1)")
	}
	dk, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", nil, errors.New("that is not a Dbrij envelope (dkenv1)")
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(body) < 28 {
		return "", nil, errors.New("that is not a Dbrij envelope (dkenv1)")
	}
	return string(dk), body, nil
}

// OpenEnvelope opens a sealed body with its data key and context.
func OpenEnvelope(dataKey, body []byte, context map[string]string) ([]byte, error) {
	aead, err := gcm(dataKey)
	if err != nil {
		return nil, err
	}
	out, err := aead.Open(nil, body[:12], body[12:], []byte(envelopePrefix+"|"+CanonicalKmsContext(context)))
	if err != nil {
		return nil, errors.New("it does not decrypt: the context differs from the one it was made with, or it was changed")
	}
	return out, nil
}
