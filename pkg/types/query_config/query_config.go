package query_config

import (
	"net"
	"time"

	whoisTypes "github.com/Motmedel/whois/pkg/types"
)

type Option func(*Config)

const (
	DefaultServer     = "whois.iana.org"
	DefaultPort       = 43
	DefaultAdditional = true
)

var (
	defaultClient = &whoisTypes.Client{
		Dialer:       net.Dialer{Timeout: 10 * time.Second},
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
)

type Config struct {
	Server     string
	Port       int
	Client     *whoisTypes.Client
	Additional bool
}

func New(options ...Option) *Config {
	config := &Config{
		Server:     DefaultServer,
		Port:       DefaultPort,
		Client:     defaultClient,
		Additional: DefaultAdditional,
	}

	for _, option := range options {
		if option != nil {
			option(config)
		}
	}

	return config
}

func WithServer(server string) Option {
	return func(config *Config) {
		config.Server = server
	}
}

func WithPort(port int) Option {
	return func(config *Config) {
		config.Port = port
	}
}

func WithClient(client *whoisTypes.Client) Option {
	return func(config *Config) {
		config.Client = client
	}
}

func WithAdditional(additional bool) Option {
	return func(config *Config) {
		config.Additional = additional
	}
}
