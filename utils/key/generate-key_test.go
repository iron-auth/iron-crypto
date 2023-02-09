package key_test

import (
	"testing"

	"github.com/iron-auth/iron-tokens/utils/key"
	a "github.com/james-elicx/go-utils/assert"
)

func TestMissingPasswordReturnsError(t *testing.T) {
	t.Parallel()

	_, err := key.Generate(key.Config{})
	a.EqualsError(t, err, "password or password buffer is required")

	_, err = key.Generate(key.Config{Password: ""})
	a.EqualsError(t, err, "password or password buffer is required")

	_, err = key.Generate(key.Config{PasswordBuffer: nil})
	a.EqualsError(t, err, "password or password buffer is required")
}

func TestMissingOptionsReturnsError(t *testing.T) {
	t.Parallel()

	_, err := key.Generate(key.Config{
		Password: "password",
	})
	a.EqualsError(t, err, "missing options")

	_, err = key.Generate(key.Config{
		Password: "password",
		Options:  key.OptionsConfig{},
	})
	a.EqualsError(t, err, "missing options")
}

func TestInvalidAlgorithmReturnsError(t *testing.T) {
	t.Parallel()

	_, err := key.Generate(key.Config{
		Password: "password",
		Options: key.OptionsConfig{
			Algorithm: 344,
		},
	})
	a.EqualsError(t, err, "invalid algorithm")
}

func TestPasswordTooShortReturnsError(t *testing.T) {
	t.Parallel()

	_, err := key.Generate(key.Config{
		Password: "password",
		Options:  key.DefaultOptions,
	})
	a.EqualsError(t, err, "password is too short")
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
	a.EqualsError(t, err, "missing salt and salt bits")

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
	a.EqualsError(t, err, "bits size must be less than 2147483648")
}

func isValidKey(t *testing.T, k key.GeneratedKey, fromBuffer bool) {
	a.NotEquals(t, k.Algorithm, "")
	a.Equals(t, k.Algorithm, key.AES256CBC)
	a.NotEquals(t, k.Key, nil)
	a.GreaterThan(t, len(k.Key), 0)
	if fromBuffer {
		a.Equals(t, k.Salt, "")
	} else {
		a.NotEquals(t, k.Salt, "")
	}
	a.NotEquals(t, k.IV, nil)
	a.GreaterThan(t, len(k.IV), 0)
}

func TestInvalidIvLengthReturnsError(t *testing.T) {
	t.Parallel()

	_, err := key.Generate(key.Config{
		Password: "passwordpasswordpasswordpasswordpasswordpasswordpasswordpassword",
		Options: key.OptionsConfig{
			Algorithm:         key.AES256CBC,
			Iterations:        2,
			MinPasswordLength: 32,
			SaltBits:          256,
			Salt:              "",
			IV:                []byte{1, 2, 3},
		},
	})
	a.EqualsError(t, err, "invalid iv length")
}

func TestGeneratesKeyAndSaltWithPassword(t *testing.T) {
	t.Parallel()

	// without specified iv
	k, err := key.Generate(key.Config{
		Password: "passwordpasswordpasswordpasswordpasswordpasswordpasswordpassword",
		Options:  key.DefaultOptions,
	})

	a.Equals(t, err, nil)
	isValidKey(t, k, false)

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
	isValidKey(t, k, false)
}

func TestGeneratesKeyAndSaltWithPasswordBuffer(t *testing.T) {
	t.Parallel()

	// too short of a buffer returns error
	_, err := key.Generate(key.Config{
		PasswordBuffer: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		Options:        key.DefaultOptions,
	})

	a.EqualsError(t, err, "key (password) buffer is too short")

	// with long enough buffer
	k, err := key.Generate(key.Config{
		PasswordBuffer: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
		Options:        key.DefaultOptions,
	})

	a.Equals(t, err, nil)
	isValidKey(t, k, true)
}

var GeneratedKeyText = "passwordpasswordpasswordpasswordpasswordpasswordpasswordpassword"
var GeneratedKey = key.GeneratedKey{
	Algorithm: key.AES256CBC,
	Key:       []byte{0xf3, 0x23, 0x9f, 0x37, 0x55, 0x29, 0x34, 0xdd, 0xfb, 0xb3, 0x61, 0xbe, 0xa4, 0x7a, 0xab, 0xc7, 0x6f, 0x62, 0x1e, 0xd2, 0x49, 0x25, 0x0e, 0x1d, 0x9d, 0xf5, 0x38, 0x20, 0x4b, 0xf1, 0x63, 0x47},
	Salt:      "b27a06366ace6bb1560ea039a5595c352a429b87f3982542da9e830a32f5468e",
	IV:        []byte{0xac, 0xc6, 0x9d, 0x62, 0x8a, 0x2b, 0x0e, 0x54, 0x55, 0x30, 0xd5, 0x82, 0xed, 0xdc, 0x49, 0x27},
}

func TestGeneratesKeyMatchingHapiIron(t *testing.T) {
	t.Parallel()

	k, err := key.Generate(key.Config{
		Password: GeneratedKeyText,
		Options: key.OptionsConfig{
			Algorithm:         key.AES256CBC,
			Iterations:        2,
			MinPasswordLength: 32,
			SaltBits:          256,
			Salt:              GeneratedKey.Salt,
			IV:                GeneratedKey.IV,
		},
	})

	a.Equals(t, err, nil)
	isValidKey(t, k, false)

	a.Equals(t, k.Algorithm, GeneratedKey.Algorithm)
	a.EqualsArray(t, k.Key, GeneratedKey.Key)
	a.Equals(t, k.Salt, GeneratedKey.Salt)
	a.EqualsArray(t, k.IV, GeneratedKey.IV)
}
