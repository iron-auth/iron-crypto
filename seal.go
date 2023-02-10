package iron

import (
	"time"

	"github.com/iron-auth/iron-crypto/encryption"
	"github.com/iron-auth/iron-crypto/key"
	"github.com/iron-auth/iron-crypto/pw"
	"github.com/iron-auth/iron-crypto/str"
	"github.com/james-elicx/go-utils/utils"
)

// Seal config options for encryption and integrity.
type SealConfigOptions struct {
	// Algorithm to use for encryption or integrity.
	//
	// AES256CBC or AES128CTR for encryption. SHA256 for integrity.
	Algorithm key.Algorithm
	// Number of iterations to use when deriving a key from the password.
	Iterations int
	// Minimum length of the password.
	MinPasswordLength int
	// Number of bits to use for the random salt.
	SaltBits int
}

// Config options for a seal.
type SealConfig struct {
	// Encryption config options.
	Encryption SealConfigOptions
	// Integrity config options.
	Integrity SealConfigOptions
	// Time to live in seconds - how long the sealed message is valid for.
	//
	// 0 means it is valid forever.
	TTL int
	// Maximum skew allowed in seconds for incoming expirations.
	//
	// Defaults to 60 seconds. Set to -1 to disable.
	TimestampSkewSec int
	// Local time offset in milliseconds.
	LocalTimeOffsetMsec int
}

var (
	// Default encryption options.
	DefaultEncryption = SealConfigOptions{
		Algorithm:         key.AES256CBC,
		Iterations:        1,
		MinPasswordLength: 32,
		SaltBits:          256,
	}
	// Default integrity options.
	DefaultIntegrity = SealConfigOptions{
		Algorithm:         key.SHA256,
		Iterations:        1,
		MinPasswordLength: 32,
		SaltBits:          256,
	}
)

// Seal a message with a password according to the options in the seal options.
//
// Returns a string that can be unsealed with the same password and options.
func Seal[T any](message T, password pw.Raw, cfg SealConfig) (string, error) {
	now := time.Now().UnixMilli() + int64(cfg.LocalTimeOffsetMsec/1000)

	messageStr, err := str.FromObject(message)
	if err != nil {
		return "", err
	}

	pass, err := pw.Normalise(password)
	if err != nil {
		return "", err
	}

	data, err := encryption.Encrypt(key.Config{
		Password:       pass.Encryption.String,
		PasswordBuffer: pass.Encryption.Buffer,
		Options: key.OptionsConfig{
			Algorithm:         cfg.Encryption.Algorithm,
			Iterations:        cfg.Encryption.Iterations,
			MinPasswordLength: cfg.Encryption.MinPasswordLength,
			SaltBits:          cfg.Encryption.SaltBits,
		},
	}, messageStr)

	if err != nil {
		return "", err
	}

	b64 := str.ToBase64(data.Encrypted)
	iv := str.ToBase64(data.Key.IV)
	expiration := utils.Ternary(cfg.TTL > 0, now+int64(cfg.TTL), 0)

	sb := encryption.SealBuilder{
		Id:         pass.Id,
		Salt:       data.Key.Salt,
		IV:         iv,
		B64:        b64,
		Expiration: expiration,
	}

	sealed, err := sb.Build(key.Config{
		Password:       pass.Integrity.String,
		PasswordBuffer: pass.Integrity.Buffer,
		Options: key.OptionsConfig{
			Algorithm:         cfg.Integrity.Algorithm,
			Iterations:        cfg.Integrity.Iterations,
			MinPasswordLength: cfg.Integrity.MinPasswordLength,
			SaltBits:          cfg.Encryption.SaltBits,
		},
	})

	return sealed, err
}
