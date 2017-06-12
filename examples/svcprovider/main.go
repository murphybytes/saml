package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/murphybytes/saml"
	"github.com/murphybytes/saml/examples/svcprovider/generated"
	"github.com/pkg/errors"
)

const exitNonSuccess = 1
const exitSuccess = 0

const certPath = "examples/svcprovider/keys/server.crt"
const keyPath = "examples/svcprovider/keys/server.key"
const homePagePath = "examples/svcprovider/pages/home.html"
const errorPagePath = "examples/svcprovider/pages/error.html"
const successPagePath = "examples/svcprovider/pages/success.html"

func main() {
	var (
		issuerURI    string
		metadataPath string
		help         bool
	)

	workingDir, err := os.Getwd()
	errHandler(err, "getting working dir")

	flag.StringVar(&issuerURI, "issuer-uri", "", "The identifier for the service provider.")
	flag.StringVar(&metadataPath, "metadata-path", fmt.Sprintf("%s/metadata.xml", workingDir), "Path of the IDP metadata file.")
	flag.BoolVar(&help, "help", false, "Show this message")
	flag.Parse()

	if help {
		flag.Usage()
		os.Exit(exitNonSuccess)
	}

	cert, err := generated.Asset(certPath)
	errHandler(err, "reading x509 cert")

	key, err := generated.Asset(keyPath)
	errHandler(err, "reading private key")

	tlsCert, err := tls.X509KeyPair(cert, key)
	errHandler(err, "creating tls cert")

	config := tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}

	metadata, err := saml.GetMetadataFromFile(metadataPath)
	errHandler(err, fmt.Sprintf("reading from %q", metadataPath))
	sp := saml.ServiceProvider{
		IssuerURI: issuerURI,
		NameIDFormats: []string{
			saml.NameIDEmail,
		},
		AssertionConsumerServiceURL: "https://localhost:8080/callback",
	}

	server := http.Server{
		Addr:      ":8080",
		TLSConfig: &config,
		Handler: func() *http.ServeMux {
			mux := http.NewServeMux()
			mux.Handle("/", newHomepageHandler())
			mux.Handle("/login", newLoginHandler(sp, metadata.IDPSSODescriptor))
			mux.Handle("/login/callback", newLoginCallbackHandler(sp, metadata.IDPSSODescriptor))
			mux.Handle("/logout", newLogoutHandler(sp, metadata))
			mux.Handle("/logout/callback", newLogoutCallbackHandler(sp, metadata))
			return mux
		}(),
	}

	errHandler(server.ListenAndServeTLS("", ""), "http listener")

}

type stackTracer interface {
	StackTrace() errors.StackTrace
}

func errHandler(err error, msg string) {
	if err != nil {
		err = errors.Wrap(err, msg)
		fmt.Println(errors.Wrap(err, msg).Error())
		if st, ok := err.(stackTracer); ok {
			fmt.Printf("%+v", st)

		}
		os.Exit(exitNonSuccess)
	}
}
