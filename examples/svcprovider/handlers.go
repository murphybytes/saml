package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"

	"github.com/murphybytes/saml"
)

type loginHandler struct {
	ssoProvider *saml.SSOProvider
}

func newLoginHandler(sp saml.ServiceProvider, metadata saml.IDPSSODescriptor) http.Handler {
	return &loginHandler{
		ssoProvider: saml.NewSSOProvider(&sp, &metadata),
	}
}

func (h *loginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	redirect, err := h.ssoProvider.RedirectBinding()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Location", redirect)
	w.WriteHeader(http.StatusFound)
}

type callbackHandler struct {
}

func newCallbackHandler() http.Handler {
	return &callbackHandler{}
}

func (h *callbackHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Println("callback")
	buffer := bytes.NewBufferString("<html><head><title>Callback</title></head><body><h1>Callback</h1></body></html>")
	io.Copy(w, buffer)

}
