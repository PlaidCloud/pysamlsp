pysamlsp
--------

**pysamlsp** is a Python library for implementing a Service Provider within a SAML2.0 SSO environment.

This package is under active development but is currently incomplete. Please don't try to use it.

Requirements
____________

Python packages
===============

* python-setuptools
* python 2.7
* lxml

and for tests:

* nose
* expecter
* dingus

Non-Python packages
===================

* xmlsec1
* openssl (though xmlsec1 may be built with GnuTLS, Libgcrypt, or NSS)
* libxml2
* libxslt

Installation
____________

Just run:

    pip install pysamlsp


Usage
_____

Initialize the class with a configuration dictionary::

    sp_config = dict( ... )

The configuration dictionary may have the following entries:

    * 'assertion_consumer_service_url': The URL of the SSO provider.
    * 'issuer': A unique identifier for the service provider; probably should match the entityID attribute of the SP metadata.
    * 'private_key': A path for the private key PEM file, required for signing AuthnRequests.
    * 'sign_authnrequests': True / False flag to indicate whether AuthnRequests should be signed.
    * 'certificate': A path for the certificate file against which a SAMLResponse signature can be verified.

Create a redirect URL with the SAMLRequest query parameter::

    sp = Pysamlsp(sp_config)
    redirect_url = sp.redirect_for_idp()

The identity provider will post to the address specified in the service providers metadata.xml. The posted field "SAMLResponse" will contain a (base64encoded, gzip'd) XML response::

    saml_response = query['SAMLResponse']
    if sp.idp_response_is_valid(saml_response):
      ...

Signed AuthnRequests
====================

If you are signing your AuthnRequests, you'll need an RSA private key. Here is a procedure for creating the keys using openssl.

Create a private key, good for 10 years::

    openssl req -x509 -days 3650 -newkey rsa:1024 -keyout saml_key_pw.pem -out saml.crt

Remove the passphrase from your new key. This library does not currently support keys with passphrases::

    openssl rsa -in saml_key_pw.pem -out saml_key.pem

Create a public key from the private key. You'll need this for metadata::

    openssl rsa -in saml_key.pem -pubout > saml.pub

