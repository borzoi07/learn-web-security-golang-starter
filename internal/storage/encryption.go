package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
)

const (
	nonceLength             = 12 // aead.NonceSize()
	authenticationTagLength = 16
)

type EncryptedPayload struct {
	Nonce      []byte
	AuthTag    []byte
	Ciphertext []byte
}

// TODO: make 2 encrypt funcs; one public, one private, and include additional randomSource argument in the private func,
// pass in rand.Reader in the public Encrypt func.
// this is to make the private encrypt func easy to test with configurable randomSource
func Encrypt(plaintext []byte, key [32]byte) (EncryptedPayload, error) {
	var block cipher.Block
	var err error
	block, err = aes.NewCipher(key[:])
	if err != nil {
		return EncryptedPayload{}, err
	}
	var aead cipher.AEAD
	aead, err = cipher.NewGCM(block)
	if err != nil {
		return EncryptedPayload{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return EncryptedPayload{}, err
	}
	sealed := aead.Seal(nil, nonce, plaintext, nil)

	return EncryptedPayload{
		Nonce:      nonce,
		AuthTag:    sealed[len(sealed)-authenticationTagLength:],
		Ciphertext: sealed[:len(sealed)-authenticationTagLength],
	}, nil
}

func Decrypt(payload EncryptedPayload, key [32]byte) ([]byte, error) {
	if len(payload.Nonce) < nonceLength || len(payload.AuthTag) < authenticationTagLength {
		return nil, errors.New("invalid encrypted payload")
	}

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	// TODO: allocate a new slice with capacity len(payload.Ciphertext)+len(payload.AuthTag) to ensure a new underlying array with append
	plaintext, err := aead.Open(nil, payload.Nonce, append(payload.Ciphertext, payload.AuthTag...), nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
