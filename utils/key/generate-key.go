package key

import (
	"crypto/sha1"

	"github.com/iron-auth/iron-tokens"
	"github.com/iron-auth/iron-tokens/utils/bits"
	"github.com/iron-auth/iron-tokens/utils/str"
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
	Algorithm algorithm
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
	Algorithm algorithm
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
	DefaultOptions = OptionsConfig{
		Algorithm:         AES256CBC,
		Iterations:        1,
		MinPasswordLength: 32,
		SaltBits:          256,
	}
)

// needed as we cannot check the struct is empty due to the iv being []byte
func isOptionsUndefined(options OptionsConfig) bool {
	return options.Algorithm == 0 && options.Iterations == 0 && options.MinPasswordLength == 0 && options.SaltBits == 0 && options.Salt == "" && options.IV == nil
}

// Generate a key to use for encryption.
func Generate(cfg Config) (GeneratedKey, error) {
	// check password is specificed
	if cfg.Password == "" && cfg.PasswordBuffer == nil {
		return GeneratedKey{}, iron.ErrPasswordRequired
	}
	if isOptionsUndefined(cfg.Options) {
		return GeneratedKey{}, iron.ErrMissingOptions
	}
	if !isAlgorithmValid(cfg.Options.Algorithm) {
		return GeneratedKey{}, iron.ErrUnsupportedAlgorithm
	}

	algo := algorithms[cfg.Options.Algorithm]

	// hmac := cfg.Options.HMAC
	// usage := []string{"encrypt", "decrypt"}
	// if hmac {
	// 	usage = []string{"sign", "verify"}
	// }

	result := GeneratedKey{Algorithm: cfg.Options.Algorithm}

	if cfg.Password != "" {
		// check password length is valid
		if len(cfg.Password) < cfg.Options.MinPasswordLength {
			return GeneratedKey{}, iron.ErrPasswordTooShort
		}

		salt := cfg.Options.Salt
		// check salt is specified
		if salt == "" {
			if cfg.Options.SaltBits == 0 {
				return GeneratedKey{}, iron.ErrMissingSalt
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
			return GeneratedKey{}, iron.ErrPasswordBufferTooShort
		}

		result.Key = cfg.PasswordBuffer
		result.Salt = ""
	}

	if cfg.Options.IV != nil {
		if (len(cfg.Options.IV) * 8) != algo.ivBits {
			return GeneratedKey{}, iron.ErrInvalidIvLength
		}

		result.IV = cfg.Options.IV
	} else if algo.ivBits > 0 {
		// generate a new IV
		iv, err := bits.RandomBits(algo.ivBits)
		if err != nil {
			return GeneratedKey{}, iron.ErrGeneratingBytes
		}

		result.IV = iv
	}

	return result, nil
}
