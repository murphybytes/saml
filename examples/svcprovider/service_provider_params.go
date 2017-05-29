package main

import (
	"encoding/xml"
	"os"

	"github.com/murphybytes/saml"
	"github.com/pkg/errors"
)

// type serviceProviderParams struct {
// 	UserEmail string `json:"user_email"`
// 	UserID    string `json:"user_id"`
// 	IssuerURI string `json:"issuer_uri"`
// }

// func newServiceProviderParams(path string) (*serviceProviderParams, error) {
// 	file, err := os.Open(path)
// 	if err != nil {
// 		return nil, errors.Wrap(err, "reading service provider file")
// 	}
// 	var spp serviceProviderParams
// 	err = json.NewDecoder(file).Decode(&spp)
// 	if err != nil {
// 		return nil, errors.Wrap(err, "decoding service provider from file")
// 	}
// 	return &spp, nil
// }

func getMetadata(path string) (*saml.EntityDescriptor, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.Wrap(err, "reading metadata")
	}
	defer file.Close()
	var metadata saml.EntityDescriptor
	err = xml.NewDecoder(file).Decode(&metadata)
	if err != nil {
		return nil, errors.Wrap(err, "decoding metadata")
	}
	return &metadata, nil
}
