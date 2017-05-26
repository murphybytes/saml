package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/pkg/errors"
)

const exitFail = 1
const exitSuccess = 0

const certPath = "examples/svcprovider/keys/server.crt"
const keyPath = "examples/svcprovider/keys/server.key"
const homePagePath = "examples/svcprovider/pages/home.html"

func main() {
	var (
		err       error
		cert, key []byte
		tlsCert   tls.Certificate
	)

	defer func() {
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(exitFail)
		}
	}()

	cert, err = Asset(certPath)
	if err != nil {
		err = errors.Wrap(err, "reading x509 cert")
		return
	}

	key, err = Asset(keyPath)
	if err != nil {
		err = errors.Wrap(err, "reading private key")
		return
	}

	tlsCert, err = tls.X509KeyPair(cert, key)
	if err != nil {
		err = errors.Wrap(err, "creating tls cert")
		return
	}

	config := tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}

	server := http.Server{
		Addr:      ":8080",
		TLSConfig: &config,
		Handler: func() *http.ServeMux {
			mux := http.NewServeMux()
			mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				page, errs := Asset(homePagePath)
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
			return mux
		}(),
	}

	err = server.ListenAndServeTLS("", "")
	if err != nil {
		err = errors.Wrap(err, "http listen")
	}

}
