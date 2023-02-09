package key_test

import (
	"testing"

	"github.com/iron-auth/iron-tokens/utils/key"
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

	Aes128ctrEncryptedPassword = []byte{0xa2, 0x0a, 0x05, 0xf5, 0x63, 0xc9, 0x03, 0x12, 0x47, 0xa0, 0x9a, 0xcf}
	Aes128ctrGeneratedKey      = key.GeneratedKey{
		Algorithm: key.AES128CTR,
		Key:       []byte{0xf3, 0x23, 0x9f, 0x37, 0x55, 0x29, 0x34, 0xdd, 0xfb, 0xb3, 0x61, 0xbe, 0xa4, 0x7a, 0xab, 0xc7},
		Salt:      "b27a06366ace6bb1560ea039a5595c352a429b87f3982542da9e830a32f5468e",
		IV:        []byte{0xac, 0xc6, 0x9d, 0x62, 0x8a, 0x2b, 0x0e, 0x54, 0x55, 0x30, 0xd5, 0x82, 0xed, 0xdc, 0x49, 0x27},
	}

	Sha256GeneratedKey = key.GeneratedKey{
		Algorithm: key.SHA256,
		Key:       []byte{0xf3, 0x23, 0x9f, 0x37, 0x55, 0x29, 0x34, 0xdd, 0xfb, 0xb3, 0x61, 0xbe, 0xa4, 0x7a, 0xab, 0xc7, 0x6f, 0x62, 0x1e, 0xd2, 0x49, 0x25, 0x0e, 0x1d, 0x9d, 0xf5, 0x38, 0x20, 0x4b, 0xf1, 0x63, 0x47},
		Salt:      "b27a06366ace6bb1560ea039a5595c352a429b87f3982542da9e830a32f5468e",
		IV:        []byte{0xac, 0xc6, 0x9d, 0x62, 0x8a, 0x2b, 0x0e, 0x54, 0x55, 0x30, 0xd5, 0x82, 0xed, 0xdc, 0x49, 0x27},
	}
)

func isValidKey(t *testing.T, k key.GeneratedKey, fromBuffer bool, algo key.Algorithm) {
	a.NotEquals(t, k.Algorithm, "")
	a.Equals(t, k.Algorithm, algo)
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
