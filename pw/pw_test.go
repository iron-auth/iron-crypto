package pw_test

import (
	"testing"

	"github.com/iron-auth/iron-crypto/ironerrors"
	"github.com/iron-auth/iron-crypto/pw"
	a "github.com/james-elicx/go-utils/assert"
)

func TestMissingPasswordReturnsError(t *testing.T) {
	t.Parallel()

	_, err := pw.Normalise(pw.Raw{})

	a.EqualsError(t, err, ironerrors.ErrPasswordRequired)
}

func TestInvalidPasswordReturnsError(t *testing.T) {
	t.Parallel()

	_, err := pw.Normalise(pw.Raw{
		Password: pw.Password{
			String: "",
		}})

	a.EqualsError(t, err, ironerrors.ErrPasswordRequired)

	_, err = pw.Normalise(pw.Raw{
		Secret: pw.Secret{
			Id: "43",
			Secret: pw.Password{
				String: "test",
			},
		}})

	a.EqualsError(t, err, ironerrors.ErrPasswordInvalid)

	_, err = pw.Normalise(pw.Raw{
		Specific: pw.Specific{
			Id: "43",
			Encryption: pw.Password{
				String: "test",
			},
			Integrity: pw.Password{
				String: "test",
			},
		},
	})

	a.EqualsError(t, err, ironerrors.ErrPasswordInvalid)
}

func TestValidPassword(t *testing.T) {
	t.Parallel()

	_, err := pw.Normalise(pw.Raw{
		Password: pw.Password{
			String: "test",
		},
	})

	a.Equals(t, err, nil)

	_, err = pw.Normalise(pw.Raw{
		Specific: pw.Specific{
			Id: "test",
			Encryption: pw.Password{
				String: "test",
			},
			Integrity: pw.Password{
				String: "test",
			},
		},
	})

	a.Equals(t, err, nil)
}

func TestNormaliseUnsealBlankPassword(t *testing.T) {
	t.Parallel()

	_, err := pw.NormaliseUnseal(pw.UnsealRaw{
		Password: pw.Password{
			String: "",
		},
	}, "test")

	a.EqualsError(t, err, ironerrors.ErrPasswordRequired)
}

func TestNormaliseUnsealString(t *testing.T) {
	t.Parallel()

	_, err := pw.NormaliseUnseal(pw.UnsealRaw{
		Password: pw.Password{
			String: "test",
		},
	}, "test")

	a.Equals(t, err, nil)
}

func TestNormaliseUnsealBuffer(t *testing.T) {
	t.Parallel()

	_, err := pw.NormaliseUnseal(pw.UnsealRaw{
		Password: pw.Password{
			Buffer: []byte{0x74, 0x65, 0x73, 0x74},
		},
	}, "test")

	a.Equals(t, err, nil)
}

func TestNormaliseUnsealListFindsId(t *testing.T) {
	t.Parallel()

	_, err := pw.NormaliseUnseal(pw.UnsealRaw{
		Map: map[string]pw.Raw{
			"testid": {
				Password: pw.Password{
					String: "test",
				},
			},
		},
	}, "testid")

	a.Equals(t, err, nil)
}

func TestNormaliseUnsealListFindsDefault(t *testing.T) {
	t.Parallel()

	_, err := pw.NormaliseUnseal(pw.UnsealRaw{
		Map: map[string]pw.Raw{
			"default": {
				Password: pw.Password{
					String: "test",
				},
			},
		},
	}, "testid")

	a.Equals(t, err, nil)
}

func TestNormaliseUnsealListFindsNone(t *testing.T) {
	t.Parallel()

	_, err := pw.NormaliseUnseal(pw.UnsealRaw{
		Map: map[string]pw.Raw{
			"wrongid": {
				Password: pw.Password{
					String: "test",
				},
			},
		},
	}, "testid")

	a.Equals(t, err, ironerrors.ErrPasswordRequired)
}

func TestNormaliseUnsealListFindsButFindsInvalidPassword(t *testing.T) {
	t.Parallel()

	_, err := pw.NormaliseUnseal(pw.UnsealRaw{
		Map: map[string]pw.Raw{
			"testid": {
				Secret: pw.Secret{
					Id: "43",
					Secret: pw.Password{
						String: "test",
					},
				},
			},
		},
	}, "testid")

	a.Equals(t, err, ironerrors.ErrPasswordInvalid)
}

func TestNormaliseUnsealListFindsValidSecret(t *testing.T) {
	t.Parallel()

	_, err := pw.NormaliseUnseal(pw.UnsealRaw{
		Map: map[string]pw.Raw{
			"testid": {
				Secret: pw.Secret{
					Id: "testid",
					Secret: pw.Password{
						String: "test",
					},
				},
			},
		},
	}, "testid")

	a.Equals(t, err, nil)
}
