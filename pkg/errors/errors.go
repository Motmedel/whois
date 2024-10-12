package errors

import "errors"

var (
	ErrNilClient   = errors.New("nil whois client")
	ErrEmptyServer = errors.New("empty server")
	ErrUnsetPort   = errors.New("unset port")
)
