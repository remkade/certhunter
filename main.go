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
	flag.BoolVar(&verbose, "verbose", false, "Print out summary of certs, including expiration dates")
	flag.Parse()
	tlsConfig = new(tls.Config)
	tlsConfig.InsecureSkipVerify = skipVerifyHostname
}

func main() {
	// Get Cert from remote server
	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", host, port), tlsConfig)

	// Failed
	if err != nil {
		fmt.Printf("Error connecting to host: %s, %s\n", host, err.Error())
		os.Exit(1)
	}

	// We use the connectionState to get the certificate info
	state := conn.ConnectionState()
	conn.Close()
	// Get the OSCP URL from the first cert (the cert for the actual site)
	ocspURL := state.PeerCertificates[0].OCSPServer[0]

	// If we're being verbose, lets print off all the certs we received with
	// the dates they are valid
	if verbose {
		fmt.Println("Got these certs:")
		for _, cert := range state.PeerCertificates {
			fmt.Printf("Cert Subject: %+v\n", cert.Subject.CommonName)
			fmt.Printf("\tNot Before: %+v\n", cert.NotBefore)
			fmt.Printf("\tNot After: %+v\n", cert.NotAfter)
		}
		fmt.Printf("Using: '%s' for OCSP URL\n", ocspURL)
	}

	// Start checking whether this cert has been revoked

	// Send Cert Request
	ocspRequest, err := ocsp.CreateRequest(state.PeerCertificates[0], state.PeerCertificates[1], nil)
	if err != nil {
		fmt.Printf("Error Generating OCSP Request: %s\n", err.Error())
		os.Exit(1)
	}

	// Then query the OSCPURL for whether the cert is revoked
	httpResponse, err := http.Get(fmt.Sprintf("%s%s", ocspURL, base64.StdEncoding.EncodeToString(ocspRequest)))
	if err != nil {
		fmt.Printf("Error GETtin OCSP Request: %s\n", err.Error())
		os.Exit(1)
	}

	// pull the response
	response, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		fmt.Printf("Error Reading all of the HTTP Response: %s\n", err.Error())
		os.Exit(1)
	}

	// Parse the OCSP response to see if it is valid
	ocspResponse, err := ocsp.ParseResponse(response, state.PeerCertificates[1])
	if err != nil {
		fmt.Printf("Error parsing OCSP Response: %s\n", err.Error())
		os.Exit(1)
	}

	// Print the certification state
	fmt.Printf("Certificate is: %s\n", statusMapping[ocspResponse.Status])
}
