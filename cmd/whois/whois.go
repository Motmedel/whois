package main

import (
	"flag"
	"fmt"
	motmedelLog "github.com/Motmedel/utils_go/pkg/log"
	whoisTypes "github.com/Motmedel/whois/pkg/types"
	"github.com/Motmedel/whois/pkg/whois"
	"log/slog"
	"net"
	"os"
	"time"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	var domain string
	flag.StringVar(&domain, "domain", "", "The domain to look up.")

	flag.Parse()

	if domain == "" {
		logger.Error("no domain was provided")
		os.Exit(1)
	}

	client := &whoisTypes.Client{
		Dialer:       net.Dialer{Timeout: 30 * time.Second},
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	result, _, err := whois.QueryDefaultWhois(domain, client, true)
	if err != nil {
		motmedelLog.LogFatal(
			"An error occurred when querying.",
			err,
			logger,
			1,
		)
	}

	fmt.Println(string(result))
}
