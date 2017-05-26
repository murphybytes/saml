# saml

Provides a pure Go implementation of the [Security Assertion Markup Language SAML 2.0](http://saml.xml.org/saml-specifications) specification.


## Development

Run the following make commands to set up your development environment and install
dependencies.
```
make deps
make generate
make test
```
`make deps` installs package dependencies.

`make generate` bundles various files in the built binary.

`make test` runs unit tests.

`make build-example` builds an example SAML service provider in build/svcprovider. 
