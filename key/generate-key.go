package key

import (
	"crypto/sha1"

	"github.com/iron-auth/iron-crypto/bits"
	"github.com/iron-auth/iron-crypto/ironerrors"
	"github.com/iron-auth/iron-crypto/str"
	"golang.org/x/crypto/pbkdf2"
)

// Key generation options.
type Config struct {
	// Password to use. If not specified, the password buffer will be used.
	Password string
	// Password buffer to use. If not specified, the password will be used.
	PasswordBuffer []byte
	// Encryption options.
	Options OptionsConfig
}

// Encryption options.
type OptionsConfig struct {
	// AES128CTR | AES256CBC | SHA256
	Algorithm Algorithm
	// Total number of iterations to use. More iterations are more secure but slower.
	Iterations int
	// Minimum password length. Shorter passwords are less secure.
	MinPasswordLength int
	// Number of bits to use in the salt. More bits are more secure but slower.
	SaltBits int
	// Salt to use. If not specified, a random salt will be generated.
	Salt string
	// IV to use. If not specified, a random IV will be generated.
	IV []byte
	// HMAC              bool
}

// Key generation result.
type GeneratedKey struct {
	// AES128CTR | AES256CBC | SHA256
	Algorithm Algorithm
	// Encryption key.
	Key []byte
	// Salt used.
	Salt string
	// IV used.
	IV []byte
}

// export const defaults: SealOptions = {
// 	encryption: { saltBits: 256, algorithm: 'aes-256-cbc', iterations: 1, minPasswordlength: 32 },
// 	integrity: { saltBits: 256, algorithm: 'sha256', iterations: 1, minPasswordlength: 32 },
// 	ttl: 0,
// 	timestampSkewSec: 60,
// 	localtimeOffsetMsec: 0,
// }

var (
	// Default options to use when generating a key.
	DefaultEncryption = OptionsConfig{
		Algorithm:         AES256CBC,
		Iterations:        1,
		MinPasswordLength: 32,
		SaltBits:          256,
	}
	// Default options to use when generating a key for integrity.
	DefaultIntegrity = OptionsConfig{
		Algorithm:         SHA256,
		Iterations:        1,
		MinPasswordLength: 32,
		SaltBits:          256,
	}
)

// NOTE: needed as we cannot check the struct is empty due to the iv being []byte
func isOptionsUndefined(options OptionsConfig) bool {
	return options.Algorithm == 0 && options.Iterations == 0 && options.MinPasswordLength == 0 && options.SaltBits == 0 && options.Salt == "" && options.IV == nil
}

// Generate a key to use for encryption.
func Generate(cfg Config) (GeneratedKey, error) {
	// check password is specificed
	if cfg.Password == "" && cfg.PasswordBuffer == nil {
		return GeneratedKey{}, ironerrors.ErrPasswordRequired
	}
	if isOptionsUndefined(cfg.Options) {
		return GeneratedKey{}, ironerrors.ErrMissingOptions
	}
	if !isAlgorithmValid(cfg.Options.Algorithm) {
		return GeneratedKey{}, ironerrors.ErrUnsupportedAlgorithm
	}

	algo := algorithms[cfg.Options.Algorithm]
	result := GeneratedKey{Algorithm: cfg.Options.Algorithm}

	if cfg.Password != "" {
		// check password length is valid
		if len(cfg.Password) < cfg.Options.MinPasswordLength {
			return GeneratedKey{}, ironerrors.ErrPasswordTooShort
		}

		salt := cfg.Options.Salt
		// check salt is specified
		if salt == "" {
			if cfg.Options.SaltBits == 0 {
				return GeneratedKey{}, ironerrors.ErrMissingSalt
			}

			// generate a new salt
			newSalt, err := bits.RandomSalt(cfg.Options.SaltBits)
			if err != nil {
				return GeneratedKey{}, err
			}
			salt = newSalt
		}

		// generate a new key
		dk := pbkdf2.Key(str.ToBuffer(cfg.Password), str.ToBuffer(salt), cfg.Options.Iterations, algo.keyBits/8, sha1.New)

		result.Key = dk
		result.Salt = salt
	} else if cfg.PasswordBuffer != nil {
		// check password length is valid
		if len(cfg.PasswordBuffer) < algo.keyBits/8 {
			return GeneratedKey{}, ironerrors.ErrPasswordBufferTooShort
		}

		result.Key = cfg.PasswordBuffer
		result.Salt = ""
	}

	if cfg.Options.IV != nil {
		result.IV = cfg.Options.IV
	} else if algo.ivBits > 0 {
		// generate a new IV
		iv, err := bits.RandomBits(algo.ivBits)
		result.IV = iv

		return result, err
	}

	return result, nil
}
