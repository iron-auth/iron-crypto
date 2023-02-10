package encryption_test

import (
	"testing"

	"github.com/iron-auth/iron-crypto/encryption"
	"github.com/iron-auth/iron-crypto/ironerrors"
	"github.com/iron-auth/iron-crypto/key"
	a "github.com/james-elicx/go-utils/assert"
)

func TestHmacWithInvalidAlgoReturnError(t *testing.T) {
	t.Parallel()

	_, err := encryption.HmacWithPassword(key.Config{
		Password: DecryptedPassword,
		Options: key.OptionsConfig{
			Algorithm:         key.AES256CBC,
			Iterations:        2,
			MinPasswordLength: 32,
			SaltBits:          256,
			Salt:              Aes256cbcGeneratedKey.Salt,
			IV:                Aes256cbcGeneratedKey.IV,
		},
	}, DecryptedMessage)
	a.EqualsError(t, err, ironerrors.ErrInvalidHmacAlgorithm)
}

func TestHmacWithValidAlgo(t *testing.T) {
	t.Parallel()

	hmac, err := encryption.HmacWithPassword(key.Config{
		Password: DecryptedPassword,
		Options: key.OptionsConfig{
			Algorithm:         key.SHA256,
			Iterations:        2,
			MinPasswordLength: 32,
			SaltBits:          256,
			Salt:              Sha256GeneratedKey.Salt,
			IV:                Sha256GeneratedKey.IV,
		},
	}, DecryptedMessage)

	a.EqualsError(t, err, nil)

	a.Equals(t, hmac.Digest, GeneratedHmac.Digest)
	a.Equals(t, hmac.Salt, GeneratedHmac.Salt)
}
