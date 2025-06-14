package whois

import (
	"context"
	"fmt"
	motmedelContext "github.com/Motmedel/utils_go/pkg/context"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	motmedelWhoisTypes "github.com/Motmedel/utils_go/pkg/whois/types"
	whoisErrors "github.com/Motmedel/whois/pkg/errors"
	whoisTypes "github.com/Motmedel/whois/pkg/types"
	"github.com/likexian/whois-parser"
	"io"
	"log/slog"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	DefaultWhoisServer = "whois.iana.org"
	DefaultWhoisPort   = 43
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
				port = DefaultWhoisPort
			} else {
				port, err = strconv.Atoi(portString)
				if err != nil {
					return "", 0
				}
			}

			return hostName, port
		} else {
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
			} else {
				return address, DefaultWhoisPort
			}
		}
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
	// TODO: Check `nil` connection?
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

	// TODO: This should be extracted from `ctx`...

	whoisContext := &motmedelWhoisTypes.WhoisContext{
		ServerAddress:   server,
		ServerIpAddress: connection.RemoteAddr().String(),
		ServerPort:      port,
		ClientIpAddress: connection.LocalAddr().String(),
		Transport:       connection.LocalAddr().Network(),
		RequestData:     writeData,
	}

	_ = connection.SetWriteDeadline(time.Now().Add(client.WriteTimeout))
	_, err = connection.Write(writeData)
	if err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("connection write: %w", err), connection, writeData)
	}

	_ = connection.SetReadDeadline(time.Now().Add(client.ReadTimeout))
	data, err := io.ReadAll(connection)
	if err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("io read all (connection): %w", err), connection)
	}

	whoisContext.ResponseData = data

	return data, nil
}

func QueryWhois(
	ctx context.Context,
	value string,
	client *whoisTypes.Client,
	serverAddress string,
	serverPort int,
	additional bool,
) ([]byte, error) {
	if value == "" {
		return nil, nil
	}

	if client == nil {
		return nil, motmedelErrors.NewWithTrace(whoisErrors.ErrNilClient)
	}

	if serverAddress == "" {
		return nil, motmedelErrors.NewWithTrace(whoisErrors.ErrEmptyServer)
	}

	if serverPort == 0 {
		return nil, motmedelErrors.NewWithTrace(whoisErrors.ErrUnsetPort)
	}

	// TODO: Support AS lookup, maybe.

	result, err := query(ctx, value, serverAddress, serverPort, client)
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

	// TODO: Need another ctx here? Use `error` with `Context` method?

	referenceResult, err := query(ctx, value, referenceServerHost, referenceServerPort, client)
	if err != nil {
		return nil, motmedelErrors.New(fmt.Errorf("query: %w", err), referenceServerHost, referenceServerPort)
	}
	if len(referenceResult) == 0 {
		return result, nil
	}

	return referenceResult, nil
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

func QueryDefaultWhois(
	ctx context.Context,
	value string,
	client *whoisTypes.Client,
	additional bool,
) ([]byte, error) {
	if value == "" {
		return nil, nil
	}

	if client == nil {
		return nil, motmedelErrors.NewWithTrace(whoisErrors.ErrNilClient)
	}

	extension := getExtension(value)
	if extension == "" {
		return nil, motmedelErrors.NewWithTrace(whoisErrors.ErrEmptyExtension)
	}

	var referenceServerHost string
	referenceServerPort := 43

	var ok bool
	extensionToServerRwMutex.RLock()
	if referenceServerHost, ok = ExtensionToServer[extension]; !ok {
		extensionToServerRwMutex.RUnlock()
		result, err := query(ctx, extension, DefaultWhoisServer, DefaultWhoisPort, client)
		if err != nil {
			return nil, motmedelErrors.New(fmt.Errorf("query: %w", err), extension)
		}
		if len(result) == 0 {
			return nil, nil
		}

		referenceServerHost, referenceServerPort = getReferenceServerHostPort(result)
		if referenceServerHost == "" || referenceServerPort == 0 {
			return nil, nil
		}

		extensionToServerRwMutex.Lock()
		ExtensionToServer[extension] = referenceServerHost
		extensionToServerRwMutex.Unlock()
	} else {
		extensionToServerRwMutex.RUnlock()
	}

	return QueryWhois(ctx, value, client, referenceServerHost, referenceServerPort, additional)
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
