package key_test

import (
	"testing"

	"github.com/iron-auth/iron-crypto/ironerrors"
	"github.com/iron-auth/iron-crypto/key"
	a "github.com/james-elicx/go-utils/assert"
)

func TestMissingPasswordReturnsError(t *testing.T) {
	t.Parallel()

	_, err := key.Generate(key.Config{})
	a.EqualsError(t, err, ironerrors.ErrPasswordRequired)

	_, err = key.Generate(key.Config{Password: ""})
	a.EqualsError(t, err, ironerrors.ErrPasswordRequired)

	_, err = key.Generate(key.Config{PasswordBuffer: nil})
	a.EqualsError(t, err, ironerrors.ErrPasswordRequired)
}

func TestMissingOptionsReturnsError(t *testing.T) {
	t.Parallel()

	_, err := key.Generate(key.Config{
		Password: "password",
	})
	a.EqualsError(t, err, ironerrors.ErrMissingOptions)

	_, err = key.Generate(key.Config{
		Password: "password",
		Options:  key.OptionsConfig{},
	})
	a.EqualsError(t, err, ironerrors.ErrMissingOptions)
}

func TestInvalidAlgorithmReturnsError(t *testing.T) {
	t.Parallel()

	_, err := key.Generate(key.Config{
		Password: "password",
		Options: key.OptionsConfig{
			Algorithm: 344,
		},
	})
	a.EqualsError(t, err, ironerrors.ErrUnsupportedAlgorithm)
}

func TestPasswordTooShortReturnsError(t *testing.T) {
	t.Parallel()

	_, err := key.Generate(key.Config{
		Password: "password",
		Options:  key.DefaultEncryption,
	})
	a.EqualsError(t, err, ironerrors.ErrPasswordTooShort)
}

func TestNoSaltOrSaltBitsReturnsError(t *testing.T) {
	t.Parallel()

	_, err := key.Generate(key.Config{
		Password: "passwordpasswordpasswordpasswordpasswordpasswordpasswordpassword",
		Options: key.OptionsConfig{
			Algorithm:         key.AES256CBC,
			Iterations:        2,
			MinPasswordLength: 32,
		},
	})
	a.EqualsError(t, err, ironerrors.ErrMissingSalt)

	_, err = key.Generate(key.Config{
		Password: "passwordpasswordpasswordpasswordpasswordpasswordpasswordpassword",
		Options: key.OptionsConfig{
			Algorithm:         key.AES256CBC,
			Iterations:        2,
			MinPasswordLength: 32,
			SaltBits:          999999999999999,
			Salt:              "",
		},
	})
	a.EqualsError(t, err, ironerrors.ErrInvalidBitsSize)
}

func TestGeneratesKeyAndSaltWithPassword(t *testing.T) {
	t.Parallel()

	// without specified iv
	k, err := key.Generate(key.Config{
		Password: "passwordpasswordpasswordpasswordpasswordpasswordpasswordpassword",
		Options:  key.DefaultEncryption,
	})

	a.Equals(t, err, nil)
	isValidKey(t, k, false, key.AES256CBC)

	// with specified iv
	k, err = key.Generate(key.Config{
		Password: "passwordpasswordpasswordpasswordpasswordpasswordpasswordpassword",
		Options: key.OptionsConfig{
			Algorithm:         key.AES256CBC,
			Iterations:        2,
			MinPasswordLength: 32,
			SaltBits:          256,
			Salt:              "",
			IV:                []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		},
	})

	a.Equals(t, err, nil)
	isValidKey(t, k, false, key.AES256CBC)
}

func TestGeneratesKeyAndSaltWithPasswordBuffer(t *testing.T) {
	t.Parallel()

	// too short of a buffer returns error
	_, err := key.Generate(key.Config{
		PasswordBuffer: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		Options:        key.DefaultEncryption,
	})

	a.EqualsError(t, err, ironerrors.ErrPasswordBufferTooShort)

	// with long enough buffer
	k, err := key.Generate(key.Config{
		PasswordBuffer: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
		Options:        key.DefaultEncryption,
	})

	a.Equals(t, err, nil)
	isValidKey(t, k, true, key.AES256CBC)
}

func TestGeneratesKeyMatchingHapiIronForAes256cbc(t *testing.T) {
	t.Parallel()

	k, err := key.Generate(key.Config{
		Password: DecryptedPassword,
		Options: key.OptionsConfig{
			Algorithm:         key.AES256CBC,
			Iterations:        2,
			MinPasswordLength: 32,
			SaltBits:          256,
			Salt:              Aes256cbcGeneratedKey.Salt,
			IV:                Aes256cbcGeneratedKey.IV,
		},
	})

	a.Equals(t, err, nil)
	isValidKey(t, k, false, key.AES256CBC)

	a.Equals(t, k.Algorithm, Aes256cbcGeneratedKey.Algorithm)
	a.EqualsArray(t, k.Key, Aes256cbcGeneratedKey.Key)
	a.Equals(t, k.Salt, Aes256cbcGeneratedKey.Salt)
	a.EqualsArray(t, k.IV, Aes256cbcGeneratedKey.IV)
}

func TestGeneratesKeyMatchingHapiIronForAes128ctr(t *testing.T) {
	t.Parallel()

	k, err := key.Generate(key.Config{
		Password: DecryptedPassword,
		Options: key.OptionsConfig{
			Algorithm:         key.AES128CTR,
			Iterations:        2,
			MinPasswordLength: 32,
			SaltBits:          256,
			Salt:              Aes128ctrGeneratedKey.Salt,
			IV:                Aes128ctrGeneratedKey.IV,
		},
	})

	a.Equals(t, err, nil)
	isValidKey(t, k, false, key.AES128CTR)

	a.Equals(t, k.Algorithm, Aes128ctrGeneratedKey.Algorithm)
	a.EqualsArray(t, k.Key, Aes128ctrGeneratedKey.Key)
	a.Equals(t, k.Salt, Aes128ctrGeneratedKey.Salt)
	a.EqualsArray(t, k.IV, Aes128ctrGeneratedKey.IV)
}

func TestGeneratesKeyMatchingHapiIronForSha256(t *testing.T) {
	t.Parallel()

	k, err := key.Generate(key.Config{
		Password: DecryptedPassword,
		Options: key.OptionsConfig{
			Algorithm:         key.SHA256,
			Iterations:        2,
			MinPasswordLength: 32,
			SaltBits:          256,
			Salt:              Sha256GeneratedKey.Salt,
			IV:                Sha256GeneratedKey.IV,
		},
	})

	a.Equals(t, err, nil)
	isValidKey(t, k, false, key.SHA256)

	a.Equals(t, k.Algorithm, Sha256GeneratedKey.Algorithm)
	a.EqualsArray(t, k.Key, Sha256GeneratedKey.Key)
	a.Equals(t, k.Salt, Sha256GeneratedKey.Salt)
	a.EqualsArray(t, k.IV, Sha256GeneratedKey.IV)
}
