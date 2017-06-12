package main

import (
	"bytes"
	"fmt"
	"html/template"
	"io"
	"net/http"

	"github.com/murphybytes/saml/examples/svcprovider/generated"
	"github.com/pkg/errors"
)

type homepageHandler struct{}

func newHomepageHandler() http.Handler {
	return &homepageHandler{}
}

func (h *homepageHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	page, errs := generated.Asset(homePagePath)
	if errs != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}
	contentTypeHeader(w)
	reader := bytes.NewReader(page)
	_, errs = io.Copy(w, reader)
	if errs != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func writeServerError(w http.ResponseWriter, err error, details string) {
	fmt.Println(errors.Wrap(err, details))
	w.WriteHeader(http.StatusInternalServerError)
}

func handleCallbackError(w http.ResponseWriter, errorText string) {
	errorPage, err := generated.Asset(errorPagePath)
	if err != nil {
		writeServerError(w, err, "reading error template")
		return
	}
	errorPageTemplate, err := template.New("").Parse(string(errorPage))
	if err != nil {
		writeServerError(w, err, "parsing error page template")
		return
	}
	err = errorPageTemplate.Execute(w, errorText)
	if err != nil {
		writeServerError(w, err, "writing error page template")
	}
}

func contentTypeHeader(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
}
