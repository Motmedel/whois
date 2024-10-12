package types

import (
	"net"
	"time"
)

type Client struct {
	Dialer       net.Dialer
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}
