# Service Provider Example
This program illustrates the usage of the saml package.
### Build
`make build-example`

### Usage
```
Usage of build/svcprovider:
  -help
    	Show this message
  -issuer-uri string
    	The identifier for the service provider.
  -metadata-path string
    	Path of the IDP metadata file. (default "/Users/someuser/metadata.xml")
```

The `issuer-uri` is an identifier for the service provider (this program).  It can be anything as long as it's
unique to the IDP.  The IDP configuration may have a field called Entity ID
where you must supply the `issuer-uri` value.  The program will use metadata
supplied by the identity provider to configure various single sign on parameters. `metadata-path`
is the path to the metadata xml file supplied by the IDP.
