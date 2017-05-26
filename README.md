# saml

Provides a pure Go implementation of the [Security Assertion Markup Language SAML 2.0](http://saml.xml.org/saml-specifications) specification.

## Service Provider Example

A SAML service provider is a program that consumes assertions from an identity provider.  For example, an
end user might try to access a web page exposed by a service provider and be redirected to an
indentity provider for authentication.  An example service provider [is included](examples/svcprovider) that
demonstrates various ways of using this package.  See the example [README](examples/svcprovider/README.md)
for details on usage. 

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
