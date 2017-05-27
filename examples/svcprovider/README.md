# Service Provider Example
This program illustrates the usage of the saml package.
### Build
`make build-example`

### Usage
```
Usage of build/svcprovider:
  -help
    	Show this message
  -params string
    	Service provider parameters (default "/Users/bob/params.json")
```
Parameters to run the service provider must be provided in a JSON formatted
file. The default for this file is params.json located in your current working
directory.  The file has the following format.

```json
{
  "user_email": "someuser@somewhere.com",
  "user_id": "someuser",
  "issuer_uri": "someprogram.somecompany.com"
}
```
`user_email` and `user_id` is the service provider user who will atttempt to authenticate
using the identity provider.  When you configure the identity provider this user
must be authorized to log in on the identity provider.  The `issuer_uri` is
an identifier for the service provider.  It can be anything as long as it's
unique to the IDP.  The IDP configuration may have a field called Entity ID
where you must supply the `issuer_uri` value. 
