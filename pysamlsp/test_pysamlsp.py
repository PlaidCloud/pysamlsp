import unittest
from expecter import expect
from datetime import datetime
from lxml import etree
import string
import base64
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
    sp = Pysamlsp({'private_key': 'support/saml_key.pem'})
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
      'sign_authnrequests': True,
      'private_key': 'support/saml_key.pem'
    })
    expect(
      sp.redirect_for_idp().\
        startswith('http://localhost?SAMLRequest=')) == True

# This test response must be signed each time it is changed. To sign it,
# find the file under support and change it there. Then pass it to xmlsec:
#   xmlsec1 --sign --pubkey-pem saml.pub --privkey-pem saml_key.pem \
#     samlresponse.xml > samlresponse_signed.xml
# Copy the contents of samlresponse_signed.xml to the block below.
TEST_SAML_RESPONSE = base64.b64encode("""
<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="identifier_2" InResponseTo="identifier_1" Version="2.0" IssueInstant="2004-12-05T09:22:05" Destination="https://sp.example.com/SAML2/SSO/POST">
  <saml:Issuer>https://idp.example.org/SAML2</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="identifier_3" Version="2.0" IssueInstant="2004-12-05T09:22:05">
    <saml:Issuer>https://idp.example.org/SAML2</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress">
        test@tartansolutions.com
      </saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData InResponseTo="identifier_1" Recipient="https://sp.example.com/SAML2/SSO/POST" NotOnOrAfter="2020-01-01T00:00:00"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2012-12-31T00:00:00Z" NotOnOrAfter="2020-01-01T00:00:00Z">
      <saml:AudienceRestriction>
        <saml:Audience>https://sp.example.com/SAML2</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="2014-01-01T00:00:00" SessionIndex="identifier_3">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>
          urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport
       </saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
  </saml:Assertion>
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:SignedInfo> 
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/> 
      <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
      <ds:Reference>
        <ds:Transforms> 
          <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/> 
          <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/> 
        </ds:Transforms> 
        <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/> 
        <ds:DigestValue>u1HBARnk8EV8ZAxThfa2WCu4tkI=</ds:DigestValue> 
      </ds:Reference> 
    </ds:SignedInfo> 
    <ds:SignatureValue>ZBCJqzmgELzOcS6HlY102s5i/Qa53/siPOMJjTOH68L5X5CcCxwF9JYWHqd0eXwd
TJ4V3tOHjX6vp5KF3DvptxS3g4GUxS2+5t1qZzNczNSZKPyNs/spFBwETSgGZxY3
cNOHd7tRERQ0y+cgyGFrpoxLmG5CedjABvMFhrmeYw4=</ds:SignatureValue> 
    <ds:KeyInfo> 
      <ds:X509Data/> 
    </ds:KeyInfo> 
  </ds:Signature>
</samlp:Response>
""")

TEST_NONSENSE_RESPONSE = base64.b64encode('<nonsense />')

class TestSAMLResponse(unittest.TestCase):
  def test_signature_verifies(self):
    sp = Pysamlsp({'certificate': 'support/saml.crt'})
    expect(sp.verify_signature(TEST_SAML_RESPONSE)) == None
  def test_signature_doesnt_verify(self):
    sp = Pysamlsp({'certificate': 'support/saml.crt'})
    with expect.raises():
      sp.verify_signature(TEST_NONSENSE_RESPONSE)
  def test_not_before_date_check(self):
    sp = Pysamlsp()
    expect(sp.check_not_before_date('2012-12-31T00:00:00Z')) == True
    expect(sp.check_not_before_date('2022-12-31T00:00:00Z')) == False
  def test_not_on_or_after_date_check(self):
    sp = Pysamlsp()
    expect(sp.check_not_on_or_after_date('2020-12-31T00:00:00Z')) == True
    expect(sp.check_not_on_or_after_date('2012-12-31T00:00:00Z')) == False
  def test_user_is_valid(self):
    sp = Pysamlsp({'certificate': 'support/saml.crt'})
    expect(sp.user_is_valid(TEST_SAML_RESPONSE)) == 'test@tartansolutions.com'
  def test_user_is_invalid(self):
    sp = Pysamlsp({'certificate': 'support/saml.crt'})
    with expect.raises(SAMLNameIDError):
      sp.user_is_valid(TEST_NONSENSE_RESPONSE)
