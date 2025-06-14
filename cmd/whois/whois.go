package main

import (
	"context"
	"flag"
	"fmt"
	motmedelLog "github.com/Motmedel/utils_go/pkg/log"
	motmedelErrorLogger "github.com/Motmedel/utils_go/pkg/log/error_logger"
	whoisTypes "github.com/Motmedel/whois/pkg/types"
	"github.com/Motmedel/whois/pkg/whois"
	"log/slog"
	"net"
	"os"
	"time"
)

func main() {
	logger := &motmedelErrorLogger.Logger{
		Logger: slog.New(
			&motmedelLog.ContextHandler{
				Next: slog.NewJSONHandler(
					os.Stderr,
					&slog.HandlerOptions{
						AddSource: false,
						Level:     slog.LevelInfo,
					},
				),
				Extractors: []motmedelLog.ContextExtractor{
					&motmedelLog.ErrorContextExtractor{},
				},
			},
		),
	}
	slog.SetDefault(logger.Logger)

	var domain string
	flag.StringVar(&domain, "domain", "", "The domain to look up.")

	flag.Parse()

	if domain == "" {
		logger.FatalWithExitingMessage("No domain provided.", nil)
	}

	client := &whoisTypes.Client{
		Dialer:       net.Dialer{Timeout: 30 * time.Second},
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	result, err := whois.QueryDefaultWhois(context.Background(), domain, client, true)
	if err != nil {
		logger.FatalWithExitingMessage(
			"An error occurred when querying.",
			fmt.Errorf("query default whois: %w", err),
		)
	}

	fmt.Println(string(result))
}
