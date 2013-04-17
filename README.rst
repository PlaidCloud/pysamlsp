# pysamlsp

**pysamlsp** is a Python library for implementing a Service Provider within a SAML2.0 SSO environment.

This package is under active development but is currently incomplete. Please don't try to use it.

## Requirements

### Python packages

* python-setuptools
* python 2.7
* lxml

and for tests:

* nose
* expecter
* dingus

### Non-Python packages

* xmlsec1
* openssl (though xmlsec1 may be built with GnuTLS, Libgcrypt, or NSS)
* libxml2

and maybe (to be confirmed)

* libxslt
* gnutls
* libgcript
* nss

## Installation

At this point in development, I have not uploaded to Pypi. Once I have, installation will be as easy as:

```
pip install pysqlsp
```

In the meantime you can clone this repository and run ```python setup.py install```.

## Use

```
cp_config = dict(

)
sp = Pysamlsp(sp_config)

...

redirect_url = sp.redirect_for_idp()

...

saml_response = query['SAMLResponse']
valid = sp.idp_response_is_valid(saml_response)
if valid:
  ...
```

### If you're signing your AuthnRequests

If you are signing your AuthnRequests, you'll need an RSA private a public key pair. Here is a procedure for creating the keys using openssl.

Create a private key:

```
openssl req -x509 -days 3650 -newkey rsa:1024 -keyout saml_key_pw.pem -out saml.crt
```

Remove the password from your new key:

```
openssl rsa -in saml_key_pw.pem -out saml_key.pem
```

Create a public key from the private key:

```
openssl rsa -in saml_key.pem -pubout > saml.pub
```

## Example application

To be determined
