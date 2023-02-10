package encryption_test

import (
	"testing"

	"github.com/iron-auth/iron-crypto/encryption"
	"github.com/iron-auth/iron-crypto/ironerrors"
	"github.com/iron-auth/iron-crypto/key"
	a "github.com/james-elicx/go-utils/assert"
)

func TestAes256cbcDecrypt(t *testing.T) {
	t.Parallel()

	data, err := encryption.Decrypt(key.Config{
		Password: DecryptedPassword,
		Options: key.OptionsConfig{
			Algorithm:         key.AES256CBC,
			Iterations:        2,
			MinPasswordLength: 32,
			SaltBits:          256,
			Salt:              Aes256cbcGeneratedKey.Salt,
			IV:                Aes256cbcGeneratedKey.IV,
		},
	}, Aes256cbcEncryptedPassword)

	a.Equals(t, err, nil)
	a.Equals(t, data, DecryptedMessage)
}

func TestAes128ctrDecrypt(t *testing.T) {
	t.Parallel()

	data, err := encryption.Decrypt(key.Config{
		Password: DecryptedPassword,
		Options: key.OptionsConfig{
			Algorithm:         key.AES128CTR,
			Iterations:        2,
			MinPasswordLength: 32,
			SaltBits:          256,
			Salt:              Aes128ctrGeneratedKey.Salt,
			IV:                Aes128ctrGeneratedKey.IV,
		},
	}, Aes128ctrEncryptedPassword)

	a.Equals(t, err, nil)
	a.Equals(t, data, DecryptedMessage)
}

func TestSha256DecryptReturnsError(t *testing.T) {
	t.Parallel()

	_, err := encryption.Encrypt(key.Config{
		Password: DecryptedPassword,
		Options: key.OptionsConfig{
			Algorithm:         key.SHA256,
			Iterations:        2,
			MinPasswordLength: 32,
			SaltBits:          256,
		},
	}, "Hello World!")

	a.Equals(t, err, ironerrors.ErrInvalidEncryptionAlgorithm)
}
