"""DNS Authenticator for Cloudflare."""
import logging

import requests
import zope.interface

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common

logger = logging.getLogger(__name__)

@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Cloudflare

    This Authenticator uses the Cloudflare API to fulfill a dns-01 challenge.
    """

    description = ('Obtain certificates using a DNS TXT record (if you are using Cloudflare for '
                   'DNS).')
    ttl = 60

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(add)
        add('credentials', help='Zhujike credentials INI file.')

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the Cloudflare API.'

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            'credentials',
            'Cloudflare credentials INI file',
            {
                'email': 'email address associated with Zhujike account',
                'token': 'API key for Zhujike account'
            }
        )

    def _perform(self, domain, validation_name, validation):
        requests.post('https://i.hostker.com/api/dnsAddRecord', {
            'email': self.credentials.conf('email'),
            'token': self.credentials.conf('token'),
            'domain': domain,
            'header': validation_name,
            'data': validation,
            'type': 'TXT',
            'ttl': self.ttl
        })

    def _cleanup(self, domain, validation_name, validation):
        domain_info = requests.post('https://i.hostker.com/api/dnsGetRecords', {
            'email': self.credentials.conf('email'),
            'token': self.credentials.conf('token'),
            'domain': domain
        }).json()
        domain_id = (i['id'] for i in domain_info if i['header'] == validation_name)
        requests.post('https://i.hostker.com/api/dnsDeleteRecord', {
            'email': self.credentials.conf('email'),
            'token': self.credentials.conf('token'),
            'id': domain_id
        })

