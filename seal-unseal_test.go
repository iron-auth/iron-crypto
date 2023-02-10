package iron_test

import (
	"strings"
	"testing"
	"time"

	"github.com/iron-auth/iron-crypto"
	"github.com/iron-auth/iron-crypto/ironerrors"
	"github.com/iron-auth/iron-crypto/key"
	"github.com/iron-auth/iron-crypto/pw"
	a "github.com/james-elicx/go-utils/assert"
)

func TestWorksWithAes256cbc(t *testing.T) {
	t.Parallel()

	sealed, err := iron.Seal(DecryptedMessage, pw.Raw{
		Password: pw.Password{
			String: DecryptedPassword,
		},
	}, iron.SealConfig{
		Encryption: iron.SealConfigOptions{
			Algorithm:         key.AES256CBC,
			Iterations:        1,
			MinPasswordLength: 32,
			SaltBits:          256,
		},
		Integrity:           SealIntegrity,
		TTL:                 0,
		TimestampSkewSec:    0,
		LocalTimeOffsetMsec: 0,
	})

	a.Equals(t, err, nil)
	a.Equals(t, len(strings.Split(sealed, "*")), 8)

	obj, err := iron.Unseal[string](sealed, pw.UnsealRaw{
		Password: pw.Password{
			String: DecryptedPassword,
		},
	}, iron.SealConfig{
		Encryption: iron.SealConfigOptions{
			Algorithm:         key.AES256CBC,
			Iterations:        1,
			MinPasswordLength: 32,
			SaltBits:          256,
		},
		Integrity:           SealIntegrity,
		TTL:                 0,
		TimestampSkewSec:    0,
		LocalTimeOffsetMsec: 0,
	})

	a.Equals(t, err, nil)
	a.Equals(t, obj, DecryptedMessage)
}

func TestWorksWithAes128ctr(t *testing.T) {
	t.Parallel()

	sealed, err := iron.Seal(DecryptedMessage, pw.Raw{
		Password: pw.Password{
			String: DecryptedPassword,
		},
	}, iron.SealConfig{
		Encryption: iron.SealConfigOptions{
			Algorithm:         key.AES128CTR,
			Iterations:        1,
			MinPasswordLength: 32,
			SaltBits:          256,
		},
		Integrity:           SealIntegrity,
		TTL:                 0,
		TimestampSkewSec:    0,
		LocalTimeOffsetMsec: 0,
	})

	a.Equals(t, err, nil)
	a.Equals(t, len(strings.Split(sealed, "*")), 8)

	obj, err := iron.Unseal[string](sealed, pw.UnsealRaw{
		Password: pw.Password{
			String: DecryptedPassword,
		},
	}, iron.SealConfig{
		Encryption: iron.SealConfigOptions{
			Algorithm:         key.AES128CTR,
			Iterations:        1,
			MinPasswordLength: 32,
			SaltBits:          256,
		},
		Integrity:           SealIntegrity,
		TTL:                 0,
		TimestampSkewSec:    0,
		LocalTimeOffsetMsec: 0,
	})

	a.Equals(t, err, nil)
	a.Equals(t, obj, DecryptedMessage)
}

func TestFailsWithIncorrectPasswordId(t *testing.T) {
	t.Parallel()

	sealed, err := iron.Seal(DecryptedMessage, pw.Raw{
		Secret: pw.Secret{
			Id: "password",
			Secret: pw.Password{
				String: DecryptedPasswordAlt,
			},
		},
	}, iron.SealConfig{
		Encryption: iron.SealConfigOptions{
			Algorithm:         key.AES128CTR,
			Iterations:        1,
			MinPasswordLength: 32,
			SaltBits:          256,
		},
		Integrity:           SealIntegrity,
		TTL:                 0,
		TimestampSkewSec:    0,
		LocalTimeOffsetMsec: 0,
	})

	a.Equals(t, err, nil)
	a.Equals(t, len(strings.Split(sealed, "*")), 8)

	_, err = iron.Unseal[string](sealed, pw.UnsealRaw{
		Map: map[string]pw.Raw{
			"password": {
				Password: pw.Password{
					String: DecryptedPassword,
				},
			},
			"passwordalt": {
				Password: pw.Password{
					String: DecryptedPasswordAlt,
				},
			},
		},
	}, iron.SealConfig{
		Encryption: iron.SealConfigOptions{
			Algorithm:         key.AES128CTR,
			Iterations:        1,
			MinPasswordLength: 32,
			SaltBits:          256,
		},
		Integrity:           SealIntegrity,
		TTL:                 0,
		TimestampSkewSec:    0,
		LocalTimeOffsetMsec: 0,
	})

	a.Equals(t, err, ironerrors.ErrBadSealHmac)
}

func TestWorksWithMultiplePasswords(t *testing.T) {
	t.Parallel()

	sealed, err := iron.Seal(DecryptedMessage, pw.Raw{
		Secret: pw.Secret{
			Id: "passwordalt",
			Secret: pw.Password{
				String: DecryptedPasswordAlt,
			},
		},
	}, iron.SealConfig{
		Encryption: iron.SealConfigOptions{
			Algorithm:         key.AES128CTR,
			Iterations:        1,
			MinPasswordLength: 32,
			SaltBits:          256,
		},
		Integrity:           SealIntegrity,
		TTL:                 0,
		TimestampSkewSec:    0,
		LocalTimeOffsetMsec: 0,
	})

	a.Equals(t, err, nil)
	a.Equals(t, len(strings.Split(sealed, "*")), 8)

	obj, err := iron.Unseal[string](sealed, pw.UnsealRaw{
		Map: map[string]pw.Raw{
			"password": {
				Password: pw.Password{
					String: DecryptedPassword,
				},
			},
			"passwordalt": {
				Password: pw.Password{
					String: DecryptedPasswordAlt,
				},
			},
		},
	}, iron.SealConfig{
		Encryption: iron.SealConfigOptions{
			Algorithm:         key.AES128CTR,
			Iterations:        1,
			MinPasswordLength: 32,
			SaltBits:          256,
		},
		Integrity:           SealIntegrity,
		TTL:                 0,
		TimestampSkewSec:    0,
		LocalTimeOffsetMsec: 0,
	})

	a.Equals(t, err, nil)
	a.Equals(t, obj, DecryptedMessage)
}

func TestWorksWithMultiplePasswordsDifferntTypes(t *testing.T) {
	t.Parallel()

	sealed, err := iron.Seal(DecryptedMessage, pw.Raw{
		Specific: pw.Specific{
			Id: "password",
			Encryption: pw.Password{
				String: DecryptedPassword,
			},
			Integrity: pw.Password{
				String: DecryptedPassword,
			},
		},
	}, iron.SealConfig{
		Encryption: iron.SealConfigOptions{
			Algorithm:         key.AES128CTR,
			Iterations:        1,
			MinPasswordLength: 32,
			SaltBits:          256,
		},
		Integrity:           SealIntegrity,
		TTL:                 0,
		TimestampSkewSec:    0,
		LocalTimeOffsetMsec: 0,
	})

	a.Equals(t, err, nil)
	a.Equals(t, len(strings.Split(sealed, "*")), 8)

	obj, err := iron.Unseal[string](sealed, pw.UnsealRaw{
		Map: map[string]pw.Raw{
			"password": {
				Specific: pw.Specific{
					Encryption: pw.Password{
						String: DecryptedPassword,
					},
					Integrity: pw.Password{
						String: DecryptedPassword,
					},
				},
			},
			"passwordalt": {
				Password: pw.Password{
					String: DecryptedPasswordAlt,
				},
			},
		},
	}, iron.SealConfig{
		Encryption: iron.SealConfigOptions{
			Algorithm:         key.AES128CTR,
			Iterations:        1,
			MinPasswordLength: 32,
			SaltBits:          256,
		},
		Integrity:           SealIntegrity,
		TTL:                 0,
		TimestampSkewSec:    0,
		LocalTimeOffsetMsec: 0,
	})

	a.Equals(t, err, nil)
	a.Equals(t, obj, DecryptedMessage)
}

func TestWorksWithMultiplePasswordsDefault(t *testing.T) {
	t.Parallel()

	sealed, err := iron.Seal(DecryptedMessage, pw.Raw{
		Password: pw.Password{
			String: DecryptedPasswordAlt,
		},
	}, iron.SealConfig{
		Encryption: iron.SealConfigOptions{
			Algorithm:         key.AES128CTR,
			Iterations:        1,
			MinPasswordLength: 32,
			SaltBits:          256,
		},
		Integrity:           SealIntegrity,
		TTL:                 0,
		TimestampSkewSec:    0,
		LocalTimeOffsetMsec: 0,
	})

	a.Equals(t, err, nil)
	a.Equals(t, len(strings.Split(sealed, "*")), 8)

	obj, err := iron.Unseal[string](sealed, pw.UnsealRaw{
		Map: map[string]pw.Raw{
			"password": {
				Password: pw.Password{
					String: DecryptedPassword,
				},
			},
			"default": {
				Password: pw.Password{
					String: DecryptedPasswordAlt,
				},
			},
		},
	}, iron.SealConfig{
		Encryption: iron.SealConfigOptions{
			Algorithm:         key.AES128CTR,
			Iterations:        1,
			MinPasswordLength: 32,
			SaltBits:          256,
		},
		Integrity:           SealIntegrity,
		TTL:                 0,
		TimestampSkewSec:    0,
		LocalTimeOffsetMsec: 0,
	})

	a.Equals(t, err, nil)
	a.Equals(t, obj, DecryptedMessage)
}

func TestTTLFailsIfExpired(t *testing.T) {
	t.Parallel()

	sealed, err := iron.Seal(DecryptedMessage, pw.Raw{
		Password: pw.Password{
			String: DecryptedPassword,
		},
	}, iron.SealConfig{
		Encryption:          iron.DefaultEncryption,
		Integrity:           iron.DefaultIntegrity,
		TTL:                 200,
		TimestampSkewSec:    -1,
		LocalTimeOffsetMsec: 0,
	})

	a.Equals(t, err, nil)
	a.Equals(t, len(strings.Split(sealed, "*")), 8)

	time.Sleep(250 * time.Millisecond)

	_, err = iron.Unseal[string](sealed, pw.UnsealRaw{
		Password: pw.Password{
			String: DecryptedPassword,
		},
	}, iron.SealConfig{
		Encryption:          iron.DefaultEncryption,
		Integrity:           iron.DefaultIntegrity,
		TTL:                 200,
		TimestampSkewSec:    -1,
		LocalTimeOffsetMsec: 0,
	})

	a.Equals(t, err, ironerrors.ErrExpiredSeal)
}

func TestTTLWorksWithSkewDisabled(t *testing.T) {
	t.Parallel()

	sealed, err := iron.Seal(DecryptedMessage, pw.Raw{
		Password: pw.Password{
			String: DecryptedPassword,
		},
	}, iron.SealConfig{
		Encryption:          iron.DefaultEncryption,
		Integrity:           iron.DefaultIntegrity,
		TTL:                 200,
		TimestampSkewSec:    -1,
		LocalTimeOffsetMsec: 0,
	})

	a.Equals(t, err, nil)
	a.Equals(t, len(strings.Split(sealed, "*")), 8)

	obj, err := iron.Unseal[string](sealed, pw.UnsealRaw{
		Password: pw.Password{
			String: DecryptedPassword,
		},
	}, iron.SealConfig{
		Encryption:          iron.DefaultEncryption,
		Integrity:           iron.DefaultIntegrity,
		TTL:                 200,
		TimestampSkewSec:    -1,
		LocalTimeOffsetMsec: 0,
	})

	a.Equals(t, err, nil)
	a.Equals(t, obj, DecryptedMessage)
}

func TestTTLWorksWithSkew(t *testing.T) {
	t.Parallel()

	sealed, err := iron.Seal(DecryptedMessage, pw.Raw{
		Password: pw.Password{
			String: DecryptedPassword,
		},
	}, iron.SealConfig{
		Encryption:          iron.DefaultEncryption,
		Integrity:           iron.DefaultIntegrity,
		TTL:                 200,
		TimestampSkewSec:    30,
		LocalTimeOffsetMsec: 0,
	})

	a.Equals(t, err, nil)
	a.Equals(t, len(strings.Split(sealed, "*")), 8)

	obj, err := iron.Unseal[string](sealed, pw.UnsealRaw{
		Password: pw.Password{
			String: DecryptedPassword,
		},
	}, iron.SealConfig{
		Encryption:          iron.DefaultEncryption,
		Integrity:           iron.DefaultIntegrity,
		TTL:                 200,
		TimestampSkewSec:    30,
		LocalTimeOffsetMsec: 0,
	})

	a.Equals(t, err, nil)
	a.Equals(t, obj, DecryptedMessage)
}

func TestTTLWorksWithSkewDisabledAndOffsetEnabled(t *testing.T) {
	t.Parallel()

	sealed, err := iron.Seal(DecryptedMessage, pw.Raw{
		Password: pw.Password{
			String: DecryptedPassword,
		},
	}, iron.SealConfig{
		Encryption:          iron.DefaultEncryption,
		Integrity:           iron.DefaultIntegrity,
		TTL:                 200,
		TimestampSkewSec:    -1,
		LocalTimeOffsetMsec: -100000,
	})

	a.Equals(t, err, nil)
	a.Equals(t, len(strings.Split(sealed, "*")), 8)

	obj, err := iron.Unseal[string](sealed, pw.UnsealRaw{
		Password: pw.Password{
			String: DecryptedPassword,
		},
	}, iron.SealConfig{
		Encryption:          iron.DefaultEncryption,
		Integrity:           iron.DefaultIntegrity,
		TTL:                 200,
		TimestampSkewSec:    -1,
		LocalTimeOffsetMsec: -100000,
	})

	a.Equals(t, err, nil)
	a.Equals(t, obj, DecryptedMessage)
}
