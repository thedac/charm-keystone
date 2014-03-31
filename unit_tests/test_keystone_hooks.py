from mock import call, patch, MagicMock
import os

from test_utils import CharmTestCase

os.environ['JUJU_UNIT_NAME'] = 'keystone'
with patch('charmhelpers.core.hookenv.config') as config:
    config.return_value = 'keystone'
    import keystone_utils as utils

_reg = utils.register_configs
_map = utils.restart_map

utils.register_configs = MagicMock()
utils.restart_map = MagicMock()

import keystone_hooks as hooks

utils.register_configs = _reg
utils.restart_map = _map

TO_PATCH = [
    # charmhelpers.core.hookenv
    'Hooks',
    'config',
    'is_relation_made',
    'log',
    'relation_ids',
    'relation_set',
    'relation_get',
    'unit_get',
    # charmhelpers.core.host
    'apt_install',
    'apt_update',
    'restart_on_change',
    # charmhelpers.contrib.openstack.utils
    'configure_installation_source',
    # charmhelpers.contrib.hahelpers.cluster_utils
    'eligible_leader',
    # keystone_utils
    'restart_map',
    'register_configs',
    'do_openstack_upgrade',
    'migrate_database',
    # other
    'check_call',
    'execd_preinstall',
    'mkdir'
]


class KeystoneRelationTests(CharmTestCase):

    def setUp(self):
        super(KeystoneRelationTests, self).setUp(hooks, TO_PATCH)
        self.config.side_effect = self.test_config.get


    def test_db_joined(self):
        self.unit_get.return_value = 'keystone.foohost.com'
        self.is_relation_made.return_value = False
        hooks.db_joined()
        self.relation_set.assert_called_with(database='keystone',
                                             username='keystone',
                                             hostname='keystone.foohost.com')
        self.unit_get.assert_called_with('private-address')

    def test_postgresql_db_joined(self):
        self.unit_get.return_value = 'keystone.foohost.com'
        self.is_relation_made.return_value = False
        hooks.pgsql_db_joined()
        self.relation_set.assert_called_with(database='keystone'),

    def test_db_joined_with_postgresql(self):
        self.is_relation_made.return_value = True

        with self.assertRaises(Exception) as context:
            hooks.db_joined()
        self.assertEqual(context.exception.message,
            'Attempting to associate a mysql database when there '
            'is already associated a postgresql one') 

    def test_postgresql_joined_with_db(self):
        self.is_relation_made.return_value = True

        with self.assertRaises(Exception) as context:
            hooks.pgsql_db_joined()
        self.assertEqual(context.exception.message,
            'Attempting to associate a postgresql database when there '
            'is already associated a mysql one') 

    @patch.object(hooks, 'CONFIGS')
    def test_db_changed_missing_relation_data(self, configs):
        configs.complete_contexts = MagicMock()
        configs.complete_contexts.return_value = []
        hooks.db_changed()
        self.log.assert_called_with(
            'shared-db relation incomplete. Peer not ready?'
        )

    @patch.object(hooks, 'CONFIGS')
    def test_postgresql_db_changed_missing_relation_data(self, configs):
        configs.complete_contexts = MagicMock()
        configs.complete_contexts.return_value = []
        hooks.pgsql_db_changed()
        self.log.assert_called_with(
            'pgsql-db relation incomplete. Peer not ready?'
        )

    def _shared_db_test(self, configs):
        configs.complete_contexts = MagicMock()
        configs.complete_contexts.return_value = ['shared-db']
        configs.write = MagicMock()
        hooks.db_changed()

    def _postgresql_db_test(self, configs):
        configs.complete_contexts = MagicMock()
        configs.complete_contexts.return_value = ['pgsql-db']
        configs.write = MagicMock()
        hooks.pgsql_db_changed()
