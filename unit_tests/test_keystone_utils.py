from mock import patch, call, MagicMock
from test_utils import CharmTestCase
from copy import deepcopy

from collections import OrderedDict
import os

os.environ['JUJU_UNIT_NAME'] = 'keystone'
with patch('charmhelpers.core.hookenv.config') as config:
    import keystone_utils as utils

import keystone_context
from charmhelpers.contrib.openstack import context

TO_PATCH = [
    'config',
    'os_release',
    'log',
]

class TestKeystoneUtils(CharmTestCase):

    def setUp(self):
        super(TestKeystoneUtils, self).setUp(utils, TO_PATCH)
        self.config.side_effect = self.test_config.get

        self.ctxt = MagicMock()
        self.rsc_map = {
            '/etc/keystone/keystone.conf': {
                'services': ['keystone'],
                'contexts': [self.ctxt],
            },
            '/etc/apache2/sites-available/openstack_https_frontend': {
                'services': ['apache2'],
                'contexts': [self.ctxt],
            },
            '/etc/apache2/sites-available/openstack_https_frontend.conf': {
                'services': ['apache2'],
                'contexts': [self.ctxt],
            }
        }

    @patch('charmhelpers.contrib.openstack.templating.OSConfigRenderer')
    @patch('os.path.exists')
    @patch.object(utils, 'resource_map')
    def test_register_configs_apache(self, resource_map, exists, renderer):
        exists.return_value = False
        self.os_release.return_value = 'havana'
        fake_renderer = MagicMock()
        fake_renderer.register = MagicMock()
        renderer.return_value = fake_renderer

        resource_map.return_value = self.rsc_map
        utils.register_configs()
        renderer.assert_called_with(
            openstack_release='havana', templates_dir='templates/')

        ex_reg = [
            call('/etc/keystone/keystone.conf', [self.ctxt]),
            call('/etc/apache2/sites-available/openstack_https_frontend', [self.ctxt]),
            call('/etc/apache2/sites-available/openstack_https_frontend.conf', [self.ctxt]),
        ]
        self.assertEquals(fake_renderer.register.call_args_list, ex_reg)

    def test_determine_ports(self):
        self.test_config.set('admin-port','80')
        self.test_config.set('service-port','81')
        result = utils.determine_ports()
        self.assertEquals(result, ['80', '81'])

    def test_determine_packages(self):
        result = utils.determine_packages()
        ex = utils.BASE_PACKAGES + ['keystone', 'haproxy', 'apache2']
        self.assertEquals(set(ex), set(result))
