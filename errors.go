package iron

import "errors"

var (
	ErrUnsupportedAlgorithm   = errors.New("unsupported algorithm")
	ErrInvalidBitsSize        = errors.New("bits size must be greater than 0 and less than 2147483648")
	ErrMissingOptions         = errors.New("missing options")
	ErrPasswordRequired       = errors.New("password or password buffer is required")
	ErrPasswordTooShort       = errors.New("password is too short")
	ErrPasswordBufferTooShort = errors.New("password buffer is too short")
	ErrMissingSalt            = errors.New("missing salt and salt bits")
	ErrInvalidIvLength        = errors.New("invalid iv length")
	ErrCreatingCipher         = errors.New("error creating cipher")
	ErrGeneratingSalt         = errors.New("error generating salt")
	ErrGeneratingBytes        = errors.New("error generating bytes")
	ErrBase64Decode           = errors.New("error base64 decoding, check input is valid base64")
)
