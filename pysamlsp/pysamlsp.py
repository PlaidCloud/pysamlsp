import os
from StringIO import StringIO
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
    return(datetime.isoformat(dt.replace(microsecond=0)))


def gzip_and_base64encode(data):
    return base64.b64encode(zlib.compress(data)[2:-4])


def base64decode_and_gunzip(data):
    return zlib.decompress(base64.b64decode(data))


class SAMLValidationError(Exception):

    """SAML signature not validated"""

    def __init__(self, msg):
        self._msg = msg

    def __str__(self):
        return '%s: %s' % (self.__doc__, self._msg)


class SAMLConditionError(Exception):

    """SAML Condition not met"""

    def __init__(self, msg):
        self._msg = msg

    def __str__(self):
        return '%s: %s' % (self.__doc__, self._msg)


class SAMLNameIDError(Exception):

    """SAML NameID error"""

    def __init__(self, msg):
        self._msg = msg

    def __str__(self):
        return '%s: %s' % (self.__doc__, self._msg)


class Pysamlsp(object):

    def __init__(self, config={}):
        # Generate a unique ID
        self.ID = uuid.uuid4().hex
        self.assertion_consumer_service_url = config.get(
            'assertion_consumer_service_url'
        ) or ''
        self.issuer = config.get('issuer') or ''
        self.private_key = config.get('private_key') or ''
        self.sign_authnrequests = config.get('sign_authnrequests') or False
        self.certificate = config.get('certificate') or ''
        self.auth_context = config.get('auth_context') or 'PasswordProtectedTransport'
        name_id_format = config.get('name_id_format')
        self.protocol_binding = config.get('protocol_binding') or 'HTTP-POST'

        if name_id_format == 'unspecified':
            self.name_id = 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified'
        elif name_id_format == 'emailAddress':
            self.name_id = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'
        elif name_id_format == 'persistent':
            self.name_id = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent'
        elif name_id_format == 'transient':
            self.name_id = 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient'
        else:
            self.name_id = None

        valid_auth_contexts = (
            'InternetProtocol',
            'InternetProtocolPassword',
            'Kerberos',
            'MobileOneFactorUnregistered',
            'MobileTwoFactorUnregistered',
            'MobileOneFactorContract',
            'MobileTwoFactorContract',
            'Password',
            'PasswordProtectedTransport',
            'PreviousSession',
            'X509',
            'PGP',
            'SPKI',
            'XMLDSig',
            'SmartcardPKI',
            'SoftwarePKI',
            'SecureRemotePassword',
            'TLSClient',
            'TimeSyncToken'
        )

        valid_binding_protocols = (
            'SOAP',
            'PAOS',
            'HTTP-REDIRECT',
            'HTTP-POST',
            'HTTP-Artifact',
            'URI'
        )

        if self.auth_context not in valid_auth_contexts:
            raise Exception('Invalid SAML Authentication Context Specified')

        if self.protocol_binding not in valid_binding_protocols:
            raise Exception('Invalid SAML Binding Protocol Specified')

        # Allow specification of the private key and cert
        # as strings so they can be passed into the object
        # rather than needing to be permanent files.
        self.certificate_str = config.get('certificate_str') or ''
        self.private_key_str = config.get('private_key_str') or ''

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
        binding_str = 'urn:oasis:names:tc:SAML:2.0:bindings:{}'.format(self.protocol_binding)
        authn_request = self.samlp_maker().AuthnRequest(
            ProtocolBinding=binding_str,
            Version='2.0',
            IssueInstant=iso_no_microseconds(datetime.utcnow()),
            ID=self.ID,
            AssertionConsumerServiceURL=self.assertion_consumer_service_url
        )

        authn_request.append(self.saml_maker().Issuer(self.issuer))

        if self.name_id is not None:
            authn_request.append(self.samlp_maker().NameIDPolicy(
                allowcreate='true',
                format=self.name_id
            ))

        requested_authn_context = self.samlp_maker().RequestedAuthnContext(
            Comparison="exact"
        )

        requested_authn_context_class_ref = \
            self.saml_maker().AuthnContextClassRef('urn:oasis:names:tc:SAML:2.0:ac:classes:{}'.format(self.auth_context))
        requested_authn_context.append(requested_authn_context_class_ref)
        authn_request.append(requested_authn_context)
        return authn_request

    def authnrequest_as_string(self):
        return etree.tostring(self.authnrequest())

    def authnrequest_to_sign(self):
        authnrequest_to_sign = self.authnrequest()
        authnrequest_to_sign.append(etree.fromstring(XML_SIGNATURE_FRAGMENT))
        return etree.tostring(authnrequest_to_sign)

    def authnrequest_signed(self):
        tempfile = '/tmp/' + self.ID

        with open(tempfile, 'w') as fh:
            fh.write(self.authnrequest_to_sign())

        # If the private key string is passed in
        # write it to a temp file so it can get processed
        # normally.
        if self.private_key_str:
            tempkey = '/tmp/' + self.ID + '_pkey'
            with open(tempkey, 'w') as fh:
                fh.write(self.private_key_str)
            self.private_key = tempkey

        signed = xmlsec1(
            '--sign',
            '--privkey-pem', self.private_key,
            tempfile
        )

        os.remove(tempfile)
        try:
            os.remove(tempkey)
        except:
            pass

        return signed.stdout

    def redirect_for_idp(self):
        if self.sign_authnrequests:
            authnrequest = self.authnrequest_signed()
        else:
            authnrequest = self.authnrequest_as_string()

        return "%s%s%s" % (
            self.assertion_consumer_service_url,
            '&' if self.assertion_consumer_service_url.find('?') > 0 else '?',
            urllib.urlencode(
                [('SAMLRequest', gzip_and_base64encode(authnrequest))]
            )
        )

    def check_not_before_date(self, when):
        return datetime.strptime(when, '%Y-%m-%dT%H:%M:%SZ') < datetime.utcnow()

    def check_not_on_or_after_date(self, when):
        return datetime.strptime(when, '%Y-%m-%dT%H:%M:%SZ') >= datetime.utcnow()

    def response_as_xml(self, saml_response):
        parser = etree.XMLParser(remove_blank_text=True)
        response = etree.parse(StringIO(base64.b64decode(saml_response)), parser)
        return etree.tostring(response, pretty_print=True)

    def verify_signature(self, saml_response):
        tempfile = '/tmp/' + self.ID

        with open(tempfile, 'w') as fh:
            fh.write(base64.b64decode(saml_response).strip())

        # If the certificate string is passed in
        # write it to a temp file so it can get processed
        # normally.
        if self.certificate_str:
            tempcert = '/tmp/' + self.ID + '_cert'
            with open(tempcert, 'w') as fh:
                fh.write(self.certificate_str)
            self.certificate = tempcert

        try:
            verified = xmlsec1(
                '--verify',
                '--pubkey-cert-pem', self.certificate,
                '--store-references',
                '--id-attr:ID', 'urn:oasis:names:tc:SAML:2.0:assertion:Assertion',
                tempfile
            )
        except:
            raise
        finally:
            if not (verified.exit_code == 0 and
                    verified.stderr.find('SignedInfo References (ok/all): 1/1') > 0):
                raise SAMLValidationError('xmlsec1 error: %s' % verified.stderr)

            os.remove(tempfile)

            try:
                os.remove(tempcert)
            except:
                pass

    def user_is_valid(self, saml_response):
        response = etree.fromstring(base64.b64decode(saml_response).strip())
        try:
            nameid = response.xpath(
                '//saml:NameID',
                namespaces={
                    'saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
                    'samlp': 'urn:oasis:names:tc:SAML:2.0:protocol'
                }
            )[0]
        except:
            raise SAMLNameIDError('NameID not given')

        try:
            condition = response.xpath(
                '/samlp:Response/saml:Assertion/saml:Conditions',
                namespaces={
                    'saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
                    'samlp': 'urn:oasis:names:tc:SAML:2.0:protocol'
                }
            )[0]
        except:
            raise SAMLConditionError('Conditions not given in response')

        if not self.check_not_before_date(
                condition.attrib.get('NotBefore', '2012-12-31T00:00:00Z')):
            raise SAMLConditionError('NotBefore condition not met')

        if not self.check_not_on_or_after_date(
                condition.attrib.get('NotOnOrAfter', None)):
            raise SAMLConditionError('NotOnOrAfter condition not met')

        self.verify_signature(saml_response)
        return nameid.text.strip()
