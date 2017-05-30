package main

import (
	"encoding/xml"
	"os"

	"github.com/murphybytes/saml"
	"github.com/pkg/errors"
)

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
