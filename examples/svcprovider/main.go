package main

import (
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
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

func main() {
	var (
		userEmail    string
		userID       string
		issuerURI    string
		metadataPath string
		help         bool
	)

	workingDir, err := os.Getwd()
	errHandler(err, "getting working dir")

	flag.StringVar(&userEmail, "email", "", "Email used for authentication.")
	flag.StringVar(&userID, "uid", "", "User ID used for authentication.")
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

	metadata, err := getMetadata(metadataPath)
	errHandler(err, "getting metadata")
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
			mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				page, errs := generated.Asset(homePagePath)
				if errs != nil {
					w.WriteHeader(http.StatusInternalServerError)
				}
				w.Header().Set("Content-Type", "text/html; charset=UTF-8")
				reader := bytes.NewReader(page)
				_, errs = io.Copy(w, reader)
				if errs != nil {
					w.WriteHeader(http.StatusInternalServerError)
				}
			})
			mux.Handle("/login", newLoginHandler(sp, metadata.IDPSSODescriptor))
			mux.Handle("/callback", newCallbackHandler())
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
