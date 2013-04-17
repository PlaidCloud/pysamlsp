import uuid
from datetime import datetime
from lxml import etree
from lxml.builder import ElementMaker

def iso_no_microseconds(dt):
  return(datetime.isoformat(dt.replace(microsecond = 0)))

class Pysamlsp(object):
  def __init__(self, config = {}):
    self.assertion_consumer_service_url = config.get(
      'assertion_consumer_service_url'
    ) or ''
    self.issuer = config.get('issuer') or ''
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
  def authnrequest_maker(self):
    authn_request = self.samlp_maker().AuthnRequest(
      ProtocolBinding = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
      Version = '2.0',
      IssueInstant = iso_no_microseconds(datetime.utcnow()),
      ID = uuid.uuid4().hex,
      AssertionConsumerServiceURL = self.assertion_consumer_service_url
    )
    authn_request.append(self.saml_maker().Issuer(self.issuer))
    requested_authn_context = self.samlp_maker().RequestedAuthnContext(
      Comparison = "exact"
    )
    requested_authn_context_class_ref = \
      self.saml_maker().AuthnContextClassRef('urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport')
    requested_authn_context.append(requested_authn_context_class_ref)
    authn_request.append(requested_authn_context)
    return etree.tostring(authn_request)

