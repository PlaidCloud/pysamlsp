# pysamlsp

**pysamlsp** is a Python library for implementing a Service Provider within a SAML2.0 SSO environment.

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
sp = pysamlsp(sp_config)

...

redirect_url = sp.redirect_for_idp()

...

saml_response = query['SAMLResponse']
valid = sp.idp_response_is_valid(saml_response)
if valid:
  ...
```

## Example application

To be determined
