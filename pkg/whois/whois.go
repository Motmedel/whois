package whois

import (
	"fmt"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	whoisErrors "github.com/Motmedel/whois/pkg/errors"
	whoisTypes "github.com/Motmedel/whois/pkg/types"
	"github.com/likexian/whois-parser"
	"io"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	defaultWhoisServer = "whois.iana.org"
	defaultWhoisPort   = 43
)

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
				port = defaultWhoisPort
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
				return address, defaultWhoisPort
			}
		}
	}

	return "", 0
}

func query(domain string, server string, port int, client *whoisTypes.Client) ([]byte, error) {
	if domain == "" {
		return nil, nil
	}

	if server == "" {
		return nil, whoisErrors.ErrEmptyServer
	}

	if port == 0 {
		return nil, whoisErrors.ErrUnsetPort
	}

	if client == nil {
		return nil, whoisErrors.ErrNilClient
	}

	queryString := domain
	if server == "whois.arin.net" {
		queryString = fmt.Sprintf("n + %s", domain)
	}

	address := net.JoinHostPort(server, strconv.Itoa(port))
	connection, err := client.Dialer.Dial("tcp", address)
	if err != nil {
		return nil, &motmedelErrors.InputError{
			Message: "An error occurred when making a connection to the whois server.",
			Cause:   err,
			Input:   address,
		}
	}
	defer connection.Close()

	_ = connection.SetWriteDeadline(time.Now().Add(client.WriteTimeout))
	writeData := []byte(queryString + "\r\n")
	_, err = connection.Write(writeData)
	if err != nil {
		return nil, &motmedelErrors.InputError{
			Message: "An error occurred when writing data to the whois server connection.",
			Cause:   err,
			Input:   writeData,
		}
	}

	_ = connection.SetReadDeadline(time.Now().Add(client.ReadTimeout))
	data, err := io.ReadAll(connection)
	if err != nil {
		return nil, &motmedelErrors.InputError{
			Message: "An error occurred when reading data from the connection.",
			Cause:   err,
			Input:   connection,
		}
	}

	return data, nil
}

func QueryWhois(value string, client *whoisTypes.Client, serverAddress string, serverPort int) ([]byte, error) {
	if value == "" {
		return nil, nil
	}

	if client == nil {
		return nil, whoisErrors.ErrNilClient
	}

	if serverAddress == "" {
		return nil, whoisErrors.ErrEmptyServer
	}

	if serverPort == 0 {
		return nil, whoisErrors.ErrUnsetPort
	}

	// TODO: Support AS lookup, maybe.

	result, err := query(value, serverAddress, serverPort, client)
	if err != nil {
		return nil, &motmedelErrors.InputError{
			Message: "An error occurred when querying the server.",
			Cause:   err,
			Input:   fmt.Sprintf("%s:%d", serverAddress, serverPort),
		}
	}
	if len(result) == 0 {
		return nil, nil
	}

	referenceServerHost, referenceServerPort := getReferenceServerHostPort(result)
	if referenceServerHost == "" || referenceServerPort == 0 {
		return result, nil
	}

	referenceResult, err := query(value, referenceServerHost, referenceServerPort, client)
	if err != nil {
		return nil, &motmedelErrors.InputError{
			Message: "An error occurred when querying a referenced server.",
			Cause:   err,
			Input:   fmt.Sprintf("%s:%d", referenceServerHost, referenceServerPort),
		}
	}
	if len(referenceResult) == 0 {
		return result, nil
	}

	return referenceResult, nil
}

func getExtension(domain string) string {
	ext := domain

	if net.ParseIP(domain) == nil {
		domains := strings.Split(domain, ".")
		ext = domains[len(domains)-1]
	}

	if strings.Contains(ext, "/") {
		ext = strings.Split(ext, "/")[0]
	}

	return ext
}

func QueryDefaultWhois(value string, client *whoisTypes.Client) ([]byte, error) {
	if value == "" {
		return nil, nil
	}

	if client == nil {
		return nil, whoisErrors.ErrNilClient
	}

	extension := getExtension(value)

	result, err := query(extension, defaultWhoisServer, defaultWhoisPort, client)
	if err != nil {
		return nil, &motmedelErrors.InputError{
			Message: "An error occurred when querying the default server.",
			Cause:   err,
			Input:   fmt.Sprintf("%s:%d", defaultWhoisServer, defaultWhoisPort),
		}
	}
	if len(result) == 0 {
		return nil, nil
	}

	referenceServerHost, referenceServerPort := getReferenceServerHostPort(result)
	if referenceServerHost == "" || referenceServerPort == 0 {
		return nil, nil
	}

	return QueryWhois(value, client, referenceServerHost, referenceServerPort)
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
