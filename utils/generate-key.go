package utils

import (
	"crypto/sha1"
	"errors"

	"golang.org/x/crypto/pbkdf2"
)

// https://github.com/brc-dd/iron-webcrypto/blob/main/src/index.ts
// https://github.com/hapijs/iron/blob/master/lib/index.js
// https://gist.github.com/enyachoke/5c60f5eebed693d9b4bacddcad693b47

type algorithm int64

const (
	AES128CTR algorithm = iota
	AES256CBC
	SHA256
)

type algorithmData struct {
	keyBits int
	ivBits  int
	name    string
}

var (
	AlgorithmData = map[algorithm]algorithmData{
		AES128CTR: {128, 128, "AES-CTR"},
		AES256CBC: {256, 128, "AES-CBC"},
		SHA256:    {256, 0, "SHA-256"},
	}
)

type generateKeyOptions struct {
	// AES128CTR | AES256CBC | SHA256
	Algorithm         algorithm
	Iterations        int
	MinPasswordLength int
	SaltBits          int
	Salt              string
	IV                []byte
	HMAC              bool
}

type generateKeyConfig struct {
	Password       string
	PasswordBuffer []byte
	Options        generateKeyOptions
}

type key struct {
	Key  []byte
	Salt string
}

func GenerateKey(cfg generateKeyConfig) (key, error) {
	// check password is specificed
	if cfg.Password == "" && cfg.PasswordBuffer == nil {
		return key{}, errors.New("password or password buffer is required")
	}

	// check algorithm is valid
	if cfg.Options.Algorithm != AES128CTR && cfg.Options.Algorithm != AES256CBC && cfg.Options.Algorithm != SHA256 {
		return key{}, errors.New("invalid algorithm")
	}

	// export const defaults: SealOptions = {
	// 	encryption: { saltBits: 256, algorithm: 'aes-256-cbc', iterations: 1, minPasswordlength: 32 },
	// 	integrity: { saltBits: 256, algorithm: 'sha256', iterations: 1, minPasswordlength: 32 },
	// 	ttl: 0,
	// 	timestampSkewSec: 60,
	// 	localtimeOffsetMsec: 0,
	// }

	algo := AlgorithmData[cfg.Options.Algorithm]

	// hmac := cfg.Options.HMAC
	// usage := []string{"encrypt", "decrypt"}
	// if hmac {
	// 	usage = []string{"sign", "verify"}
	// }

	if cfg.Password != "" {
		// check password length is valid
		if len(cfg.Password) < cfg.Options.MinPasswordLength {
			return key{}, errors.New("password is too short")
		}

		salt := cfg.Options.Salt
		// check salt is specified
		if salt == "" {
			if cfg.Options.SaltBits == 0 {
				return key{}, errors.New("missing salt and salt bits")
			}

			b, err := NewRandomBits(cfg.Options.SaltBits)
			if err != nil {
				return key{}, err
			}

			// generate a new salt
			salt, err = b.GetRandomSalt()
			if err != nil {
				return key{}, err
			}
		}

		// generate a new key
		dk := pbkdf2.Key([]byte(cfg.Password), []byte(salt), cfg.Options.Iterations, algo.keyBits/8, sha1.New)

		return key{
			Key:  dk,
			Salt: salt,
		}, nil

	} else if cfg.PasswordBuffer != nil {
		// check password length is valid
		if len(cfg.PasswordBuffer) < algo.keyBits/8 {
			return key{}, errors.New("password buffer is too short")
		}

		// result.key = await _crypto.subtle.importKey('raw', password, id, false, usage);
	}

	return key{}, errors.New("uh-oh")
}
