package key

import (
	"crypto/sha1"
	"errors"

	"github.com/iron-auth/iron-tokens/utils/bits"
	"golang.org/x/crypto/pbkdf2"
)

// https://github.com/brc-dd/iron-webcrypto/blob/main/src/index.ts
// https://github.com/hapijs/iron/blob/master/lib/index.js
// https://gist.github.com/enyachoke/5c60f5eebed693d9b4bacddcad693b47

type GenerateKeyConfig struct {
	Password       string
	PasswordBuffer []byte
	Options        GenerateKeyConfigOptions
}

type GenerateKeyConfigOptions struct {
	// AES128CTR | AES256CBC | SHA256
	Algorithm         Algorithm
	Iterations        int
	MinPasswordLength int
	SaltBits          int
	Salt              string
	IV                []byte
	// HMAC              bool
}

type Key struct {
	Algorithm Algorithm
	Key       []byte
	Salt      string
	IV        []byte
}

// export const defaults: SealOptions = {
// 	encryption: { saltBits: 256, algorithm: 'aes-256-cbc', iterations: 1, minPasswordlength: 32 },
// 	integrity: { saltBits: 256, algorithm: 'sha256', iterations: 1, minPasswordlength: 32 },
// 	ttl: 0,
// 	timestampSkewSec: 60,
// 	localtimeOffsetMsec: 0,
// }

var (
	GenerateKeyConfigOptionsDefaults = GenerateKeyConfigOptions{
		Algorithm:         AES256CBC,
		Iterations:        1,
		MinPasswordLength: 32,
		SaltBits:          256,
	}
)

// needed as we cannot check the struct is empty due to the iv being []byte
func isOptionsUndefined(options GenerateKeyConfigOptions) bool {
	return options.Algorithm == 0 && options.Iterations == 0 && options.MinPasswordLength == 0 && options.SaltBits == 0 && options.Salt == "" && options.IV == nil
}

// check algorithm is valid
func isAlgorithmValid(algorithm Algorithm) bool {
	return algorithm == AES128CTR || algorithm == AES256CBC || algorithm == SHA256
}

func GenerateKey(cfg GenerateKeyConfig) (Key, error) {
	// check password is specificed
	if cfg.Password == "" && cfg.PasswordBuffer == nil {
		return Key{}, errors.New("password or password buffer is required")
	}
	if isOptionsUndefined(cfg.Options) {
		return Key{}, errors.New("missing options")
	}
	if !isAlgorithmValid(cfg.Options.Algorithm) {
		return Key{}, errors.New("invalid algorithm")
	}

	algo := AlgorithmData[cfg.Options.Algorithm]

	// hmac := cfg.Options.HMAC
	// usage := []string{"encrypt", "decrypt"}
	// if hmac {
	// 	usage = []string{"sign", "verify"}
	// }

	result := Key{Algorithm: cfg.Options.Algorithm}

	if cfg.Password != "" {
		// check password length is valid
		if len(cfg.Password) < cfg.Options.MinPasswordLength {
			return Key{}, errors.New("password is too short")
		}

		salt := cfg.Options.Salt
		// check salt is specified
		if salt == "" {
			if cfg.Options.SaltBits == 0 {
				return Key{}, errors.New("missing salt and salt bits")
			}

			// generate a new salt
			newSalt, err := bits.RandomSalt(cfg.Options.SaltBits)
			if err != nil {
				return Key{}, err
			}
			salt = newSalt
		}

		// generate a new key
		dk := pbkdf2.Key([]byte(cfg.Password), []byte(salt), cfg.Options.Iterations, algo.keyBits/8, sha1.New)

		result.Key = dk
		result.Salt = salt
	} else if cfg.PasswordBuffer != nil {
		// check password length is valid
		if len(cfg.PasswordBuffer) < algo.keyBits/8 {
			return Key{}, errors.New("key (password) buffer is too short")
		}

		result.Key = cfg.PasswordBuffer
		result.Salt = ""
	}

	if cfg.Options.IV != nil {
		if (len(cfg.Options.IV) * 8) != algo.ivBits {
			return Key{}, errors.New("invalid iv length")
		}

		result.IV = cfg.Options.IV
	} else if algo.ivBits > 0 {
		// generate a new IV
		iv, err := bits.RandomBits(algo.ivBits)
		if err != nil {
			return Key{}, err
		}

		result.IV = iv
	}

	return result, nil
}
