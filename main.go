package main

import (
	"code.google.com/p/go.crypto/ocsp"
	"encoding/base64"
	"crypto/tls"
	"io/ioutil"
	"net/http"
	"flag"
	"fmt"
	"os"
//	"time"
)

var host string
var port int
var verbose bool
var skipVerifyHostname bool
var tlsConfig *tls.Config
var statusMapping = [3]string{"Valid", "Revoked", "Unknown"}

func init() {
	flag.StringVar(&host, "host", "localhost", "Hostname to connect to")
	flag.IntVar(&port, "port", 443, "Port to connect to")
	flag.BoolVar(&skipVerifyHostname, "skip-host-verify", false, "Skip verifying the certificate hostname")
	flag.BoolVar(&verbose, "verbose", false, "Print out summary of cert")
	flag.Parse()
	tlsConfig = new(tls.Config)
	tlsConfig.InsecureSkipVerify = skipVerifyHostname
}

func main() {
	// Get Cert from remote server
	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", host, port), tlsConfig)

	if err != nil {
		fmt.Printf("Error connecting to host: %s, %s\n", host, err.Error())
		os.Exit(1)
	}

	state := conn.ConnectionState()
	conn.Close()
	// Verify that we actually have certs
	if len(state.PeerCertificates) < 1 {
		fmt.Printf("Problem getting certificates!\nI got: %+v\n")
		os.Exit(1)
	}

	// Get Intermediate Certs
	var ocspURL string
	if len(state.PeerCertificates[0].OCSPServer) > 1 {
		ocspURL = state.PeerCertificates[0].OCSPServer[0]
	}
	if verbose {
		fmt.Println("Got these certs:")
		for _, cert := range state.PeerCertificates {
			fmt.Printf("Cert Subject: %+v\n", cert.Subject.CommonName)
			fmt.Printf("\tNot Before: %+v\n", cert.NotBefore)
			fmt.Printf("\tNot After: %+v\n", cert.NotAfter)
		}
		if ocspURL != "" {
			fmt.Printf("Using: '%s' for OCSP URL\n", ocspURL)
		} else {
			fmt.Printf("Did not find any OSCP URLs in certificate.\n")
		}
	}
	// Send Cert Request
	if ocspURL != "" {
		ocspRequest, err := ocsp.CreateRequest(state.PeerCertificates[0], state.PeerCertificates[1], nil)
		if err != nil {
			fmt.Printf("Error Generating OCSP Request: %s\n", err.Error())
			os.Exit(1)
		}
		httpResponse, err := http.Get(fmt.Sprintf("%s%s", ocspURL, base64.StdEncoding.EncodeToString(ocspRequest)))
		if err != nil {
			fmt.Printf("Error GETtin OCSP Request: %s\n", err.Error())
			os.Exit(1)
		}
		response, err := ioutil.ReadAll(httpResponse.Body)
		if err != nil {
			fmt.Printf("Error Reading all of the HTTP Response: %s\n", err.Error())
			os.Exit(1)
		}
		ocspResponse, err := ocsp.ParseResponse(response, state.PeerCertificates[1])
		if err != nil {
			fmt.Printf("Error parsing OCSP Response: %s\n", err.Error())
			os.Exit(1)
		}
		fmt.Printf("Certificate is: %s\n", statusMapping[ocspResponse.Status])
	}
}

/*
func isValidNow(notBefore time.Time, notAfter time.Time) bool {
	now := time.Now()
	return now.Before(notAfter) && now.After(notBefore)
}
*/
