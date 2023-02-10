package encryption_test

import (
	"testing"

	"github.com/iron-auth/iron-crypto/encryption"
	"github.com/iron-auth/iron-crypto/ironerrors"
	"github.com/iron-auth/iron-crypto/key"
	a "github.com/james-elicx/go-utils/assert"
)

func TestAes256cbcEncrypt(t *testing.T) {
	t.Parallel()

	data, err := encryption.Encrypt(key.Config{
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

	a.Equals(t, err, nil)
	a.EqualsArray(t, data.Encrypted, Aes256cbcEncryptedPassword)

	a.Equals(t, data.Key.Algorithm, Aes256cbcGeneratedKey.Algorithm)
	a.EqualsArray(t, data.Key.Key, Aes256cbcGeneratedKey.Key)
	a.Equals(t, data.Key.Salt, Aes256cbcGeneratedKey.Salt)
	a.EqualsArray(t, data.Key.IV, Aes256cbcGeneratedKey.IV)
}

func TestAes128ctrEncrypt(t *testing.T) {
	t.Parallel()

	data, err := encryption.Encrypt(key.Config{
		Password: DecryptedPassword,
		Options: key.OptionsConfig{
			Algorithm:         key.AES128CTR,
			Iterations:        2,
			MinPasswordLength: 32,
			SaltBits:          256,
			Salt:              Aes128ctrGeneratedKey.Salt,
			IV:                Aes128ctrGeneratedKey.IV,
		},
	}, DecryptedMessage)

	a.Equals(t, err, nil)
	a.EqualsArray(t, data.Encrypted, Aes128ctrEncryptedPassword)

	a.Equals(t, data.Key.Algorithm, Aes128ctrGeneratedKey.Algorithm)
	a.EqualsArray(t, data.Key.Key, Aes128ctrGeneratedKey.Key)
	a.Equals(t, data.Key.Salt, Aes128ctrGeneratedKey.Salt)
	a.EqualsArray(t, data.Key.IV, Aes128ctrGeneratedKey.IV)
}

func TestSha256EncryptReturnsError(t *testing.T) {
	t.Parallel()

	_, err := encryption.Encrypt(key.Config{
		Password: DecryptedPassword,
		Options: key.OptionsConfig{
			Algorithm:         key.SHA256,
			Iterations:        2,
			MinPasswordLength: 32,
			SaltBits:          256,
		},
	}, DecryptedMessage)

	a.Equals(t, err, ironerrors.ErrInvalidEncryptionAlgorithm)
}

func TestEncryptFailForInvalidPassword(t *testing.T) {
	t.Parallel()

	_, err := encryption.Encrypt(key.Config{
		Password: "",
		Options: key.OptionsConfig{
			Algorithm:         key.AES256CBC,
			Iterations:        2,
			MinPasswordLength: 32,
			SaltBits:          256,
			Salt:              Aes256cbcGeneratedKey.Salt,
			IV:                Aes256cbcGeneratedKey.IV,
		},
	}, DecryptedMessage)

	a.Equals(t, err, ironerrors.ErrPasswordRequired)
}
