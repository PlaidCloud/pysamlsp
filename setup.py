from setuptools import setup
from pysamlsp import __version__

setup(
  name = 'pysamlsp',
  version = __version__,
  author = "Rob Martin @version2beta",
  author_email = "rob@version2beta.com",
  description = "A service provider implementation for SAML2.0.",
  long_description = open('README.md').read(),
  license = "LICENSE.txt",
  keywords = "saml service provider",
  packages = ['pysamlsp'],
  install_requires = [
    'lxml'
  ],
  test_requires = [
    'nose',
    'expecter',
    'dingus'
  ],
  package_data = {
    '': ['*.dist'],
  }
)

