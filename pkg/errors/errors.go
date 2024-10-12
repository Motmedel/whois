package errors

import (
	"errors"
	whoisparser "github.com/likexian/whois-parser"
)

var (
	ErrNilClient   = errors.New("nil whois client")
	ErrEmptyServer = errors.New("empty server")
	ErrUnsetPort   = errors.New("unset port")
)

var (
	ErrNotFoundDomain    = whoisparser.ErrNotFoundDomain
	ErrReservedDomain    = whoisparser.ErrReservedDomain
	ErrPremiumDomain     = whoisparser.ErrPremiumDomain
	ErrBlockedDomain     = whoisparser.ErrBlockedDomain
	ErrDomainDataInvalid = whoisparser.ErrDomainDataInvalid
	ErrDomainLimitExceed = whoisparser.ErrDomainLimitExceed
)
