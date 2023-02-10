package iron_test

import (
	"strings"
	"testing"

	"github.com/iron-auth/iron-crypto"
	"github.com/iron-auth/iron-crypto/key"
	"github.com/iron-auth/iron-crypto/pw"
	a "github.com/james-elicx/go-utils/assert"
)

var (
	DecryptedPassword = "passwordpasswordpasswordpasswordpasswordpasswordpasswordpassword"
	DecryptedMessage  = "Hello World!"
)

var (
	Aes256cbcEncryptedPassword = []byte{0x87, 0x09, 0x6a, 0xbb, 0xec, 0x0c, 0x53, 0x01, 0x79, 0xd2, 0x74, 0x48, 0xba, 0xdb, 0x55, 0x5f}
	Aes256cbcGeneratedKey      = key.GeneratedKey{
		Algorithm: key.AES256CBC,
		Key:       []byte{0xf3, 0x23, 0x9f, 0x37, 0x55, 0x29, 0x34, 0xdd, 0xfb, 0xb3, 0x61, 0xbe, 0xa4, 0x7a, 0xab, 0xc7, 0x6f, 0x62, 0x1e, 0xd2, 0x49, 0x25, 0x0e, 0x1d, 0x9d, 0xf5, 0x38, 0x20, 0x4b, 0xf1, 0x63, 0x47},
		Salt:      "b27a06366ace6bb1560ea039a5595c352a429b87f3982542da9e830a32f5468e",
		IV:        []byte{0xac, 0xc6, 0x9d, 0x62, 0x8a, 0x2b, 0x0e, 0x54, 0x55, 0x30, 0xd5, 0x82, 0xed, 0xdc, 0x49, 0x27},
	}
)

var (
	SealEncryption = iron.SealConfigOptions{
		Algorithm:         key.AES256CBC,
		Iterations:        2,
		MinPasswordLength: 32,
		SaltBits:          256,
	}
	SealIntegrity = iron.SealConfigOptions{
		Algorithm:         key.SHA256,
		Iterations:        2,
		MinPasswordLength: 32,
		SaltBits:          256,
	}
)

var (
	SealedFromNode          = "Fe26.2**6a0a8428b61b9e81c6a6e2556771a9c6a95bf4a68f028c08100e53a5187f8d04*lxsszOvWyix-6nMuIu1LuA*8RcBvCQJWJZAROQMFHydnQ**e74b0b23724cb4b9f98e740fbb1d7bf8c6fabaf2bfa256e4ad639651c43c3338*m8PCQ8EmX4QKLTqL0WYPycKTdE5-encTlU45QbNcz40"
	InvalidJsonSealedFromGo = "Fe26.2**cd1f3fc21662f8e50a8b55c6df349d4966d2184782c7250eb71f61b2d8a490d7*daqwINv4U_jDow1nquETpg*c0f4pPDgbGLaRLuPBVrRVA**0eb59f59358b399f503f9a6e256b98939be96681158e49af6efdf33b13832d9b*kxgs8FVxhWv9V_DO1UTyR9FuyBQKH3fbDabWyN1__Fw"
	ValidJsonSealedFromGo   = "Fe26.2**5c8074c7968402902cb644d2c552a416ae73d0b29af8215b7c98ecbe1c86af31*S8yjbJgU7Xgn-zjsen1TiQ*edmvCzfh3K5AAULEerrLvw**304664241a9d67c92c8589f49aeb0aa90af672c8e144ccdef4b04a4473fa1d08*xwzfk-UCjZXVNRqenqJXCuxxcXabRkaTp1WwI8nLrLc"
)

func TestSeal(t *testing.T) {
	t.Parallel()

	sealed, err := iron.Seal(DecryptedMessage, pw.Raw{
		Password: pw.Password{
			String: DecryptedPassword,
		},
	}, iron.SealConfig{
		Encryption:          SealEncryption,
		Integrity:           SealIntegrity,
		TTL:                 0,
		TimestampSkewSec:    0,
		LocalTimeOffsetMsec: 0,
	})

	a.Equals(t, err, nil)

	a.Equals(t, len(strings.Split(sealed, "*")), 8)
	a.Equals(t, len(strings.Split(sealed, "*")), len(strings.Split(SealedFromNode, "*")))
}
