package whois

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	motmedelContext "github.com/Motmedel/utils_go/pkg/context"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	motmedelNetErrors "github.com/Motmedel/utils_go/pkg/net/errors"
	"github.com/Motmedel/utils_go/pkg/utils"
	motmedelWhoisContext "github.com/Motmedel/utils_go/pkg/whois/context"
	motmedelWhoisTypes "github.com/Motmedel/utils_go/pkg/whois/types"
	whoisErrors "github.com/Motmedel/whois/pkg/errors"
	whoisTypes "github.com/Motmedel/whois/pkg/types"
	"github.com/Motmedel/whois/pkg/types/query_config"
	"github.com/likexian/whois-parser"
)

var ExtensionToServer = map[string]string{
	"se":  "whois.iis.se",
	"com": "whois.verisign-grs.com",
	"net": "whois.verisign-grs.com",
	"org": "whois.publicinterestregistry.net",
	"nu":  "whois.iis.nu",
}

var extensionToServerRwMutex sync.RWMutex

var referenceServerPattern = regexp.MustCompile(`(?:Registrar WHOIS Server:|whois:|ReferralServer:|refer:) ?(.+)`)

func getReferenceServerHostPort(whoisResult []byte) (string, int) {
	if len(whoisResult) == 0 {
		return "", 0
	}

	if match := referenceServerPattern.FindSubmatch(whoisResult); match != nil {
		parsedUrl, err := url.Parse(strings.TrimSpace(string(match[1])))
		if err != nil {
			return "", 0
		}

		var hostName string
		var port int

		if parsedUrl.Scheme != "" {
			hostName = parsedUrl.Hostname()
			if hostName == "" {
				return "", 0
			}

			if path := parsedUrl.Path; path != "" {
				if path == "/whois" && hostName == "porkpun.com" {
					hostName = "whois.porkpun.com"
				} else {
					return "", 0
				}
			}

			if hostName == "whois.godaddy" {
				hostName = "whois.godaddy.com"
			}

			portString := parsedUrl.Port()
			if portString == "" {
				port = query_config.DefaultPort
			} else {
				port, err = strconv.Atoi(portString)
				if err != nil {
					return "", 0
				}
			}

			return hostName, port
		}

		address := parsedUrl.Path
		if address == "" {
			return "", 0
		}

		if strings.Contains(hostName, ":") {
			addressSplit := strings.Split(hostName, ":")
			hostName = addressSplit[0]
			portString := addressSplit[1]
			port, err = strconv.Atoi(portString)
			if err != nil {
				return "", 0
			}

			return hostName, port
		}

		return address, query_config.DefaultPort
	}

	return "", 0
}

func query(
	ctx context.Context,
	domain string,
	server string,
	port int,
	client *whoisTypes.Client,
) ([]byte, error) {
	if domain == "" {
		return nil, nil
	}

	if server == "" {
		return nil, motmedelErrors.NewWithTrace(whoisErrors.ErrEmptyServer)
	}

	if port == 0 {
		return nil, motmedelErrors.NewWithTrace(whoisErrors.ErrUnsetPort)
	}

	if client == nil {
		return nil, motmedelErrors.NewWithTrace(whoisErrors.ErrNilClient)
	}

	queryString := domain
	if server == "whois.arin.net" {
		queryString = fmt.Sprintf("n + %s", domain)
	}

	address := net.JoinHostPort(server, strconv.Itoa(port))
	dialer := client.Dialer

	connection, err := dialer.Dial("tcp", address)
	if err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("dialer dial: %w", err), address, dialer)
	}
	if utils.IsNil(connection) {
		return nil, motmedelErrors.NewWithTrace(motmedelNetErrors.ErrNilConn)
	}
	defer func() {
		if err := connection.Close(); err != nil {
			slog.WarnContext(
				motmedelContext.WithErrorContextValue(
					ctx,
					motmedelErrors.NewWithTrace(fmt.Errorf("connection close: %w", err), connection),
				),
				"An error occurred when closing a connection.",
			)
		}
	}()

	writeData := []byte(queryString + "\r\n")

	baseWhoisContext := &motmedelWhoisTypes.WhoisContext{
		ServerAddress:   server,
		ServerIpAddress: connection.RemoteAddr().String(),
		ServerPort:      port,
		ClientIpAddress: connection.LocalAddr().String(),
		Transport:       connection.LocalAddr().Network(),
		RequestData:     writeData,
	}

	whoisContext, ok := ctx.Value(motmedelWhoisContext.Key).(*motmedelWhoisTypes.WhoisContext)
	if ok {
		whoisContext.ServerAddress = baseWhoisContext.ServerAddress
		whoisContext.ServerIpAddress = baseWhoisContext.ServerIpAddress
		whoisContext.ServerPort = baseWhoisContext.ServerPort
		whoisContext.ClientIpAddress = baseWhoisContext.ClientIpAddress
		whoisContext.Transport = baseWhoisContext.Transport
		whoisContext.RequestData = baseWhoisContext.RequestData
	} else {
		whoisContext = baseWhoisContext
	}

	ctx = context.WithValue(ctx, motmedelWhoisContext.Key, whoisContext)

	if err := connection.SetWriteDeadline(time.Now().Add(client.WriteTimeout)); err != nil {
		return nil, motmedelErrors.NewWithTraceCtx(
			ctx,
			fmt.Errorf("connection set write deadline: %w", err),
			connection,
		)
	}
	_, err = connection.Write(writeData)
	if err != nil {
		return nil, motmedelErrors.NewWithTraceCtx(
			ctx,
			fmt.Errorf("connection write: %w", err),
			connection,
			writeData,
		)
	}

	if err := connection.SetReadDeadline(time.Now().Add(client.ReadTimeout)); err != nil {
		return nil, motmedelErrors.NewWithTraceCtx(
			ctx,
			fmt.Errorf("connection set read deadline: %w", err),
			connection,
		)
	}
	data, err := io.ReadAll(connection)
	if err != nil {
		return nil, motmedelErrors.NewWithTraceCtx(
			ctx,
			fmt.Errorf("io read all (connection): %w", err),
			connection,
		)
	}

	whoisContext.ResponseData = data

	return data, nil
}

func getExtension(domain string) string {
	extension := domain

	if net.ParseIP(domain) == nil {
		domains := strings.Split(domain, ".")
		extension = domains[len(domains)-1]
	}

	if strings.Contains(extension, "/") {
		extension = strings.Split(extension, "/")[0]
	}

	return extension
}

func Query(
	ctx context.Context,
	value string,
	client *whoisTypes.Client,
	additional bool,
	options ...query_config.Option,
) ([]byte, error) {
	if value == "" {
		return nil, nil
	}

	if client == nil {
		return nil, motmedelErrors.NewWithTrace(whoisErrors.ErrNilClient)
	}

	config := query_config.New(options...)

	server := config.Server
	port := config.Port

	if server == query_config.DefaultServer && port == query_config.DefaultPort {
		extension := getExtension(value)
		if extension == "" {
			return nil, motmedelErrors.NewWithTrace(whoisErrors.ErrEmptyExtension)
		}

		extensionToServerRwMutex.RLock()
		extensionServer, ok := ExtensionToServer[extension]
		if ok {
			extensionToServerRwMutex.RUnlock()
			server = extensionServer
		} else {
			extensionToServerRwMutex.RUnlock()
			result, err := query(ctx, extension, server, port, client)
			if err != nil {
				return nil, motmedelErrors.New(fmt.Errorf("query: %w", err), extension)
			}
			if len(result) == 0 {
				return nil, nil
			}

			server, port = getReferenceServerHostPort(result)
			if server == "" || port == 0 {
				return nil, nil
			}

			extensionToServerRwMutex.Lock()
			ExtensionToServer[extension] = server
			extensionToServerRwMutex.Unlock()
		}
	}

	result, err := query(ctx, value, server, port, client)
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}
	if len(result) == 0 {
		return nil, nil
	}

	if !additional {
		return result, nil
	}

	referenceServerHost, referenceServerPort := getReferenceServerHostPort(result)
	if referenceServerHost == "" || referenceServerPort == 0 {
		return result, nil
	}

	referenceResult, err := query(ctx, value, referenceServerHost, referenceServerPort, client)
	if err != nil {
		return nil, motmedelErrors.New(fmt.Errorf("query: %w", err), referenceServerHost, referenceServerPort)
	}
	if len(referenceResult) == 0 {
		return result, nil
	}

	return referenceResult, nil
}

func Parse(whoisResult []byte) (*whoisparser.WhoisInfo, error) {
	if len(whoisResult) == 0 {
		return nil, nil
	}

	whoisResultString := string(whoisResult)
	parsedResult, err := whoisparser.Parse(whoisResultString)
	if err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("whoisparser parse: %w", err), whoisResultString)
	}

	return &parsedResult, nil
}
