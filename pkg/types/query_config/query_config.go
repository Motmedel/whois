package query_config

type Option func(*Config)

const (
	DefaultServer = "whois.iana.org"
	DefaultPort   = 43
)

type Config struct {
	Server string
	Port   int
}

func New(options ...Option) *Config {
	config := &Config{
		Server: DefaultServer,
		Port:   DefaultPort,
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
