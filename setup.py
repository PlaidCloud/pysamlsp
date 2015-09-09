from setuptools import setup
try:
    from sh import xmlsec1
except:
    print "IMPORTANT: the xmlsec1 system package is required by this library. Please remember to also install it through whatever means are appropriate on your operating system."


setup(
    name='pysamlsp',
    version='0.1.4',
    author="Rob Martin @version2beta",
    author_email="rob@version2beta.com",
    description="A service provider implementation for SAML2.0.",
    long_description=open('README.rst').read(),
    url='http://pypi.python.org/pypi/pysamlsp',
    license="LICENSE.txt",
    keywords="SAML2 SSO single sign on service provider only, for use with a remote IdP.",
    packages=['pysamlsp'],
    install_requires=[
        'lxml',
        'sh'
    ],
    tests_require=[
        'nose',
        'expecter',
        'dingus'
    ],
    include_package_data=True
)
