package fawsecurity

// Wire-compatible hardened FAWSEC1 private-report envelope. Not archive encryption.
import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"errors"
)

var envelopeMagic = []byte("FAWSEC1\x00")

const envelopeLimit = 32 << 20

func Seal(plain, password []byte) ([]byte, error) {
	if len(password) == 0 || len(password) > 4096 || len(plain) > envelopeLimit {
		return nil, errors.New("invalid password or report size")
	}
	salt := make([]byte, 16)
	if _, e := rand.Read(salt); e != nil {
		return nil, e
	}
	key, e := pbkdf2.Key(sha256.New, string(password), salt, 200000, 32)
	if e != nil {
		return nil, e
	}
	defer clear(key)
	block, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	gcm, e := cipher.NewGCM(block)
	if e != nil {
		return nil, e
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return nil, e
	}
	out := append([]byte{}, envelopeMagic...)
	out = append(out, salt...)
	out = append(out, nonce...)
	return gcm.Seal(out, nonce, plain, nil), nil
}
func Open(blob, password []byte) ([]byte, error) {
	if len(password) == 0 || len(password) > 4096 || len(blob) < 52 || len(blob) > envelopeLimit+52 || string(blob[:8]) != string(envelopeMagic) {
		return nil, errors.New("invalid FAWSEC envelope or password")
	}
	key, e := pbkdf2.Key(sha256.New, string(password), blob[8:24], 200000, 32)
	if e != nil {
		return nil, e
	}
	defer clear(key)
	block, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	gcm, e := cipher.NewGCM(block)
	if e != nil {
		return nil, e
	}
	return gcm.Open(nil, blob[24:36], blob[36:], nil)
}
