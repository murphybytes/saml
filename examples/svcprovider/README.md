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

`email` and `uid` are identifiers for the user who will authenticate
using the identity provider.  When you configure the identity provider this user
must be authorized to log in on to the identity provider.  `issuer-uri` is
an identifier for the service provider (this program).  It can be anything as long as it's
unique to the IDP.  The IDP configuration may have a field called Entity ID
where you must supply the `issuer-uri` value. The program will use metadata
supplied by the identity provider to configure various single sign on parameters. `metadata-path`
is the path to the metadata xml file supplied by the IDP.
