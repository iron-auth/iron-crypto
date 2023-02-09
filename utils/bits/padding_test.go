package bits_test

import (
	"testing"

	"github.com/iron-auth/iron-tokens/utils/bits"
	a "github.com/james-elicx/go-utils/assert"
)

func TestPad(t *testing.T) {
	t.Parallel()

	padded := bits.Pad([]byte{0x01, 0x02, 0x03}, 8)

	a.Equals(t, len(padded), 8)
	a.EqualsArray(t, padded, []byte{0x01, 0x02, 0x03, 0x05, 0x05, 0x05, 0x05, 0x05})
}

func TestUnpad(t *testing.T) {
	t.Parallel()

	padded := bits.Pad([]byte{0x01, 0x02, 0x03}, 8)
	unpadded := bits.Unpad(padded)
	a.EqualsArray(t, unpadded, []byte{0x01, 0x02, 0x03})

	padded = bits.Pad([]byte{0x01, 0x02, 0x03}, 1)
	unpadded = bits.Unpad(padded)
	a.EqualsArray(t, unpadded, []byte{0x01, 0x02, 0x03})

	padded = bits.Pad([]byte{0x01, 0x02, 0x03}, 3)
	unpadded = bits.Unpad(padded)
	a.EqualsArray(t, unpadded, []byte{0x01, 0x02, 0x03})
}
