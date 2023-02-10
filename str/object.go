package str

import (
	"encoding/json"

	"github.com/iron-auth/iron-crypto/ironerrors"
)

// Converts anything of type T to a string.
func FromObject[T any](v T) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", ironerrors.ErrMarshallingObject
	}

	return FromBuffer(b), nil
}

// Converts a string to anything of type T.
func ToObject[T any](v string) (T, error) {
	var obj T

	if err := json.Unmarshal(ToBuffer(v), &obj); err != nil {
		return obj, ironerrors.ErrUnmarshallingObject
	}

	return obj, nil
}
