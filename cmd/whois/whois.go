package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	motmedelLog "github.com/Motmedel/utils_go/pkg/log"
	motmedelErrorLogger "github.com/Motmedel/utils_go/pkg/log/error_logger"
	whoisTypes "github.com/Motmedel/whois/pkg/types"
	"github.com/Motmedel/whois/pkg/whois"
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
		Dialer:       net.Dialer{Timeout: 10 * time.Second},
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	result, err := whois.Query(context.Background(), domain, client, true)
	if err != nil {
		logger.FatalWithExitingMessage(
			"An error occurred when querying.",
			fmt.Errorf("whois query: %w", err),
			domain,
			client,
		)
	}

	if len(result) == 0 {
		return
	}

	fmt.Println(string(result))
}
