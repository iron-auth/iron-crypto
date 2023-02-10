package iron

import (
	"time"

	"github.com/iron-auth/iron-crypto/encryption"
	"github.com/iron-auth/iron-crypto/key"
	"github.com/iron-auth/iron-crypto/pw"
	"github.com/iron-auth/iron-crypto/str"
	"github.com/james-elicx/go-utils/utils"
)

type SealConfigOptions struct {
	Algorithm         key.Algorithm
	Iterations        int
	MinPasswordLength int
	SaltBits          int
}

type SealConfig struct {
	Encryption          SealConfigOptions
	Integrity           SealConfigOptions
	TTL                 int
	TimestampSkewSec    int
	LocalTimeOffsetMsec int
}

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

	if err != nil {
		return "", err
	}

	return sealed, nil
}
