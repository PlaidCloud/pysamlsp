import unittest
from expecter import expect
from datetime import datetime
from lxml import etree
import string
from pysamlsp import *

def setUpmodule():
  pass

class TestUtilityFunctions(unittest.TestCase):
  def test_iso_now_no_microseconds(self):
    dt = datetime(2013, 4, 17, 14, 15, 53, 32711)
    expect(iso_no_microseconds(dt)) == '2013-04-17T14:15:53'

class TestPysamlspAuthnRequestRoot(unittest.TestCase):
  def test_the_root_element_namespace(self):
    sp = Pysamlsp()
    ar = etree.fromstring(sp.authnrequest_as_string())
    expect(ar.tag) == '{urn:oasis:names:tc:SAML:2.0:protocol}AuthnRequest'
  def test_the_root_ProtocolBinding_attribute(self):
    sp = Pysamlsp()
    ar = etree.fromstring(sp.authnrequest_as_string())
    expect(ar.get('ProtocolBinding')) == 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'
  def test_the_root_Version_attribute(self):
    sp = Pysamlsp()
    ar = etree.fromstring(sp.authnrequest_as_string())
    expect(ar.get('Version')) == '2.0'
  def test_the_root_IssueInstant_attribute(self):
    sp = Pysamlsp()
    ar = etree.fromstring(sp.authnrequest_as_string())
    expect(ar.get('IssueInstant')) == iso_no_microseconds(datetime.utcnow())
  def test_the_root_ID_attribute(self):
    sp = Pysamlsp()
    ar = etree.fromstring(sp.authnrequest_as_string())
    expect(all(c in string.hexdigits for c in ar.get('ID')))
    expect(len(ar.get('ID'))) == 32
  def test_the_root_AssertionConsumerServiceURL_attribute(self):
    sp = Pysamlsp({'assertion_consumer_service_url': 'http://localhost'})
    ar = etree.fromstring(sp.authnrequest_as_string())
    expect(ar.get('AssertionConsumerServiceURL')) == 'http://localhost'

class TestPysamlspIssuerElement(unittest.TestCase):
  def test_the_element_namespace(self):
    sp = Pysamlsp()
    ar = etree.fromstring(sp.authnrequest_as_string())
    expect(ar[0].tag) == '{urn:oasis:names:tc:SAML:2.0:assertion}Issuer'
  def test_the_element_text(self):
    sp = Pysamlsp({'issuer': 'http://localhost/SAML'})
    ar = etree.fromstring(sp.authnrequest_as_string())
    expect(ar[0].text) == 'http://localhost/SAML'

class TestPysamlspNameIDPolicyElement(unittest.TestCase):
  def test_the_element_namespace(self):
    sp = Pysamlsp()
    ar = etree.fromstring(sp.authnrequest_as_string())
    expect(ar[1].tag) == \
      '{urn:oasis:names:tc:SAML:2.0:protocol}NameIDPolicy'
  def test_the_root_allowcreate_attribute(self):
    sp = Pysamlsp()
    ar = etree.fromstring(sp.authnrequest_as_string())
    expect(ar[1].get('allowcreate')) == 'true'
  def test_the_root_format_attribute(self):
    sp = Pysamlsp()
    ar = etree.fromstring(sp.authnrequest_as_string())
    expect(ar[1].get('format')) == \
      'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'

class TestPysamlspRequestedAuthnContextElement(unittest.TestCase):
  def test_the_element_namespace(self):
    sp = Pysamlsp()
    ar = etree.fromstring(sp.authnrequest_as_string())
    expect(ar[2].tag) == \
      '{urn:oasis:names:tc:SAML:2.0:protocol}RequestedAuthnContext'
  def test_the_element_Comparison_attribute(self):
    sp = Pysamlsp()
    ar = etree.fromstring(sp.authnrequest_as_string())
    expect(ar[2].get('Comparison')) == 'exact'
  def test_the_child_element_text(self):
    sp = Pysamlsp()
    ar = etree.fromstring(sp.authnrequest_as_string())
    expect(ar[2][0].text) == \
      'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'

class TestAuthnRequestToSign(unittest.TestCase):
  def test_signature_element(self):
    sp = Pysamlsp()
    ar = etree.fromstring(sp.authnrequest_to_sign())
    expect(
      ar.xpath( "ds:Signature",
        namespaces = {'ds': 'http://www.w3.org/2000/09/xmldsig#'})[0].tag
    ) == '{http://www.w3.org/2000/09/xmldsig#}Signature'

class TestAuthnSignedRequest(unittest.TestCase):
  def test_signed_element(self):
    sp = Pysamlsp({'public_key': 'support/saml.pub',
      'private_key': 'support/saml_key.pem'})
    ar = etree.fromstring(sp.authnrequest_signed())
    expect(len(ar.xpath( "//ds:SignatureValue",
        namespaces = {'ds': 'http://www.w3.org/2000/09/xmldsig#'}))) > 0

class TestGzipAndBase64(unittest.TestCase):
  def test_gzip_and_base64(self):
    expect(
      base64decode_and_gunzip(
        gzip_and_base64encode("<root>Test</root>")
      )
    ) == "<root>Test</root>"

class TestRedirectForIdP(unittest.TestCase):
  def test_redirect(self):
    sp = Pysamlsp({
      'assertion_consumer_service_url': 'http://localhost',
      'signed': True,
      'public_key': 'support/saml.pub',
      'private_key': 'support/saml_key.pem'
    })
    expect(
      sp.redirect_for_idp().\
        startswith('http://localhost?SAMLRequest=')) == True

