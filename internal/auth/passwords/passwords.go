package passwords

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const MaxLength = 128

const (
	argon2MemKiB      = 19 << 10
	argon2Iter        = 2
	argon2Parallelism = 1
	argon2KeyLen      = 32
)

func Hash(password string) (string, error) {
	if utf8.RuneCountInString(password) > MaxLength {
		return "", fmt.Errorf("password must not exceed %d characters", MaxLength)
	}

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	return encodeArgon2idHash(argon2idHash{
		version:     argon2.Version,
		memoryKiB:   argon2MemKiB,
		iterations:  argon2Iter,
		parallelism: argon2Parallelism,
		salt:        salt,
		derivedKey:  argon2.IDKey([]byte(password), salt, argon2Iter, argon2MemKiB, argon2Parallelism, argon2KeyLen),
	}), nil
}

func Verify(password, encodedHash string) bool {
	if utf8.RuneCountInString(password) > MaxLength {
		return false
	}
	if legacyExpectedHash, ok := decodeLegacyHash(encodedHash); ok {
		candidateHash := sha256.Sum256([]byte(password))
		return subtle.ConstantTimeCompare(candidateHash[:], legacyExpectedHash) == 1
	}

	expArgon2idHash, valid := parseArgon2idHash(encodedHash)
	if !valid || expArgon2idHash.version != argon2.Version {
		return false
	}

	candidateKey := argon2.IDKey(
		[]byte(password),
		expArgon2idHash.salt,
		expArgon2idHash.iterations,
		expArgon2idHash.memoryKiB,
		expArgon2idHash.parallelism,
		uint32(len(expArgon2idHash.derivedKey)),
	)
	return subtle.ConstantTimeCompare(candidateKey, expArgon2idHash.derivedKey) == 1
}

func NeedsRehash(encodedHash string) bool {
	if _, isLegacy := decodeLegacyHash(encodedHash); isLegacy {
		return true
	}

	argon2idHash, isValid := parseArgon2idHash(encodedHash)
	if !isValid {
		// malformed hashes are not the responsibility of this function
		return false
	}

	return argon2idHash.version != argon2.Version ||
		argon2idHash.iterations != argon2Iter ||
		argon2idHash.memoryKiB != argon2MemKiB ||
		argon2idHash.parallelism != argon2Parallelism ||
		len(argon2idHash.derivedKey) != argon2KeyLen
}
