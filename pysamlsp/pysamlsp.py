import os
import base64
import zlib
import uuid
import urllib
from sh import xmlsec1
from datetime import datetime
from lxml import etree
from lxml.builder import ElementMaker

XML_SIGNATURE_FRAGMENT = """
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
      <ds:DigestValue /> 
    </ds:Reference> 
  </ds:SignedInfo> 
  <ds:SignatureValue /> 
  <ds:KeyInfo> 
    <ds:X509Data /> 
  </ds:KeyInfo> 
</ds:Signature>
"""

def iso_no_microseconds(dt):
  return(datetime.isoformat(dt.replace(microsecond = 0)))

def gzip_and_base64encode(data):
  return base64.b64encode(zlib.compress(data))

def base64decode_and_gunzip(data):
  return zlib.decompress(base64.b64decode(data))

class Pysamlsp(object):
  def __init__(self, config = {}):
    self.ID = uuid.uuid4().hex
    self.assertion_consumer_service_url = config.get(
      'assertion_consumer_service_url'
    ) or ''
    self.issuer = config.get('issuer') or ''
    self.private_key = config.get('private_key') or ''
    self.public_key = config.get('public_key') or ''
    self.signed = config.get('signed') or False
  def samlp_maker(self):
    return ElementMaker(
      namespace='urn:oasis:names:tc:SAML:2.0:protocol',
      nsmap=dict(samlp='urn:oasis:names:tc:SAML:2.0:protocol'),
    )
  def saml_maker(self):
    return ElementMaker(
      namespace='urn:oasis:names:tc:SAML:2.0:assertion',
      nsmap=dict(saml='urn:oasis:names:tc:SAML:2.0:assertion'),
    )
  def authnrequest(self):
    authn_request = self.samlp_maker().AuthnRequest(
      ProtocolBinding = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
      Version = '2.0',
      IssueInstant = iso_no_microseconds(datetime.utcnow()),
      ID = self.ID,
      AssertionConsumerServiceURL = self.assertion_consumer_service_url
    )
    authn_request.append(self.saml_maker().Issuer(self.issuer))
    authn_request.append(self.samlp_maker().NameIDPolicy(
      allowcreate='true',
      format='urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'
    ))
    requested_authn_context = self.samlp_maker().RequestedAuthnContext(
      Comparison = "exact"
    )
    requested_authn_context_class_ref = \
      self.saml_maker().AuthnContextClassRef('urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport')
    requested_authn_context.append(requested_authn_context_class_ref)
    authn_request.append(requested_authn_context)
    return authn_request
  def authnrequest_as_string(self):
    return etree.tostring(self.authnrequest())
  def authnrequest_to_sign(self):
    authnrequest_to_sign = self.authnrequest()
    authnrequest_to_sign.append(
      etree.fromstring(XML_SIGNATURE_FRAGMENT))
    return etree.tostring(authnrequest_to_sign)
  def authnrequest_signed(self):
    tempfile = '/tmp/' + self.ID
    with open(tempfile, 'w') as fh:
      fh.write(self.authnrequest_to_sign())
    signed = xmlsec1(
        '--sign',
        '--privkey-pem', self.private_key,
        '--pubkey-pem', self.public_key,
        tempfile)
    os.remove(tempfile)
    return signed.stdout
  def redirect_for_idp(self):
    if self.signed:
      authnrequest = self.authnrequest_signed()
    else:
      authnrequest = self.authnrequest_as_string()
    return "%s?%s" % (
      self.assertion_consumer_service_url,
      urllib.urlencode(
        [('SAMLRequest', gzip_and_base64encode(authnrequest))]
      )
    )

