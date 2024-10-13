package whois

import (
	"fmt"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	motmedelWhoisTypes "github.com/Motmedel/utils_go/pkg/whois/types"
	whoisErrors "github.com/Motmedel/whois/pkg/errors"
	whoisTypes "github.com/Motmedel/whois/pkg/types"
	"github.com/likexian/whois-parser"
	"io"
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
	domain string,
	server string,
	port int,
	client *whoisTypes.Client,
) ([]byte, *motmedelWhoisTypes.WhoisContext, error) {
	if domain == "" {
		return nil, nil, nil
	}

	if server == "" {
		return nil, nil, whoisErrors.ErrEmptyServer
	}

	if port == 0 {
		return nil, nil, whoisErrors.ErrUnsetPort
	}

	if client == nil {
		return nil, nil, whoisErrors.ErrNilClient
	}

	queryString := domain
	if server == "whois.arin.net" {
		queryString = fmt.Sprintf("n + %s", domain)
	}

	address := net.JoinHostPort(server, strconv.Itoa(port))
	connection, err := client.Dialer.Dial("tcp", address)
	if err != nil {
		return nil, nil, &motmedelErrors.InputError{
			Message: "An error occurred when making a connection to the whois server.",
			Cause:   err,
			Input:   []any{"tcp", address},
		}
	}
	defer connection.Close()

	writeData := []byte(queryString + "\r\n")

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
		return nil, whoisContext, &motmedelErrors.InputError{
			Message: "An error occurred when writing data to the whois server connection.",
			Cause:   err,
			Input:   writeData,
		}
	}

	_ = connection.SetReadDeadline(time.Now().Add(client.ReadTimeout))
	data, err := io.ReadAll(connection)
	if err != nil {
		return nil, whoisContext, &motmedelErrors.CauseError{
			Message: "An error occurred when reading data from the connection.",
			Cause:   err,
		}
	}

	whoisContext.ResponseData = data

	return data, whoisContext, nil
}

func QueryWhois(
	value string,
	client *whoisTypes.Client,
	serverAddress string,
	serverPort int,
	additional bool,
) ([]byte, *motmedelWhoisTypes.WhoisContext, error) {
	if value == "" {
		return nil, nil, nil
	}

	if client == nil {
		return nil, nil, whoisErrors.ErrNilClient
	}

	if serverAddress == "" {
		return nil, nil, whoisErrors.ErrEmptyServer
	}

	if serverPort == 0 {
		return nil, nil, whoisErrors.ErrUnsetPort
	}

	// TODO: Support AS lookup, maybe.

	result, whoisContext, err := query(value, serverAddress, serverPort, client)
	if err != nil {
		return nil, whoisContext, &motmedelErrors.InputError{
			Message: "An error occurred when querying the server.",
			Cause:   err,
			Input:   []any{value, serverAddress, serverPort, client},
		}
	}
	if len(result) == 0 {
		return nil, whoisContext, nil
	}

	if !additional {
		return result, whoisContext, nil
	}

	referenceServerHost, referenceServerPort := getReferenceServerHostPort(result)
	if referenceServerHost == "" || referenceServerPort == 0 {
		return result, whoisContext, nil
	}

	referenceResult, referenceWhoisContext, err := query(value, referenceServerHost, referenceServerPort, client)
	if err != nil {
		return nil, referenceWhoisContext, &motmedelErrors.InputError{
			Message: "An error occurred when querying a referenced server.",
			Cause:   err,
			Input:   []any{value, referenceServerHost, referenceServerPort, client},
		}
	}
	if len(referenceResult) == 0 {
		return result, whoisContext, nil
	}

	return referenceResult, referenceWhoisContext, nil
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
	value string,
	client *whoisTypes.Client,
	additional bool,
) ([]byte, *motmedelWhoisTypes.WhoisContext, error) {
	if value == "" {
		return nil, nil, nil
	}

	if client == nil {
		return nil, nil, whoisErrors.ErrNilClient
	}

	extension := getExtension(value)
	if extension == "" {
		return nil, nil, whoisErrors.ErrEmptyExtension
	}

	var referenceServerHost string
	referenceServerPort := 43

	var ok bool
	extensionToServerRwMutex.RLock()
	if referenceServerHost, ok = ExtensionToServer[extension]; !ok {
		extensionToServerRwMutex.RUnlock()
		result, whoisContext, err := query(extension, DefaultWhoisServer, DefaultWhoisPort, client)
		if err != nil {
			return nil, whoisContext, &motmedelErrors.InputError{
				Message: "An error occurred when querying the default server.",
				Cause:   err,
				Input:   []any{extension, DefaultWhoisServer, DefaultWhoisPort, client},
			}
		}
		if len(result) == 0 {
			return nil, whoisContext, nil
		}

		referenceServerHost, referenceServerPort = getReferenceServerHostPort(result)
		if referenceServerHost == "" || referenceServerPort == 0 {
			return nil, whoisContext, nil
		}

		extensionToServerRwMutex.Lock()
		ExtensionToServer[extension] = referenceServerHost
		extensionToServerRwMutex.Unlock()
	} else {
		extensionToServerRwMutex.RUnlock()
	}

	return QueryWhois(value, client, referenceServerHost, referenceServerPort, additional)
}

func Parse(whoisResult []byte) (*whoisparser.WhoisInfo, error) {
	if len(whoisResult) == 0 {
		return nil, nil
	}

	whoisResultString := string(whoisResult)
	parsedResult, err := whoisparser.Parse(whoisResultString)
	if err != nil {
		return nil, &motmedelErrors.InputError{
			Message: "An error occurred when parsing the whois result.",
			Cause:   err,
			Input:   whoisResultString,
		}
	}

	return &parsedResult, nil
}
