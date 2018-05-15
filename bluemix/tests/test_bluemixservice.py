# Copyright 2013 Cloudbase Solutions Srl
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.


import importlib
import os
import unittest

try:
    import unittest.mock as mock
except ImportError:
    import mock

from bluemix import bluemixservice
from cloudbaseinit import exception
from cloudbaseinit.tests import testutils
from cloudbaseinit.metadata.services import base

from six.moves.urllib import error


class TestBluemixService(unittest.TestCase):

    def setUp(self):
        module_path = "bluemix.bluemixservice"
        self.service_module = importlib.import_module(module_path)
        self._service = self.service_module.BluemixService()
        self.snatcher = testutils.LogSnatcher(module_path)

    def _test_preprocess_options(self, fail=False):
        if fail:
            with testutils.ConfPatcher("types", ["vfat", "ntfs"],
                                       group="config_drive"):
                with self.assertRaises(exception.CloudbaseInitException):
                    self._service._preprocess_options()
            with testutils.ConfPatcher("locations", ["device"],
                                       group="config_drive"):
                with self.assertRaises(exception.CloudbaseInitException):
                    self._service._preprocess_options()
            return

        options = {
            "raw_hdd": False,
            "cdrom": False,
            "vfat": True,
            # Deprecated options above.
            "types": ["vfat", "iso"],
            "locations": ["partition"]
        }
        contexts = [testutils.ConfPatcher(key, value, group="config_drive")
                    for key, value in options.items()]
        with contexts[0], contexts[1], contexts[2], \
                contexts[3], contexts[4]:
            self._service._preprocess_options()
            self.assertEqual({"vfat", "iso"},
                             self._service._searched_types)
            self.assertEqual({"hdd", "partition"},
                             self._service._searched_locations)

    def test_preprocess_options_fail(self):
        self._test_preprocess_options(fail=True)

    def test_preprocess_options(self):
        self._test_preprocess_options()

    @mock.patch('cloudbaseinit.metadata.services.osconfigdrive.factory.'
                'get_config_drive_manager')
    def test_load(self, mock_get_config_drive_manager):
        mock_manager = mock.MagicMock()
        mock_manager.get_config_drive_files.return_value = True
        fake_path = "fake\\fake_id"
        mock_manager.target_path = fake_path
        mock_get_config_drive_manager.return_value = mock_manager
        expected_log = [
            "Metadata copied to folder: %r" % fake_path]

        with self.snatcher:
            response = self._service.load()

        mock_get_config_drive_manager.assert_called_once_with()
        mock_manager.get_config_drive_files.assert_called_once_with(
            searched_types=self.service_module.CD_TYPES,
            searched_locations=self.service_module.CD_LOCATIONS)
        self.assertEqual(expected_log, self.snatcher.output)
        self.assertTrue(response)
        self.assertEqual(fake_path, self._service._metadata_path)

    @mock.patch('os.path.normpath')
    @mock.patch('os.path.join')
    def test_get_data(self, mock_join, mock_normpath):
        fake_path = os.path.join('fake', 'path')
        with mock.patch('six.moves.builtins.open',
                        mock.mock_open(read_data='fake data'), create=True):
            response = self._service._get_data(fake_path)
            self.assertEqual('fake data', response)
            mock_join.assert_called_with(
                self._service._metadata_path, fake_path)
            mock_normpath.assert_called_once_with(mock_join.return_value)

    @mock.patch('shutil.rmtree')
    def test_cleanup(self, mock_rmtree):
        fake_path = os.path.join('fake', 'path')
        self._service._metadata_path = fake_path
        mock_mgr = mock.Mock()
        self._service._mgr = mock_mgr
        mock_mgr.target_path = fake_path
        with self.snatcher:
            self._service.cleanup()
        self.assertEqual(["Deleting metadata folder: %r" % fake_path],
                         self.snatcher.output)
        mock_rmtree.assert_called_once_with(fake_path,
                                            ignore_errors=True)
        self.assertEqual(None, self._service._metadata_path)

    def test_get_password_path(self):
        response = self._service._get_password_path()
        self.assertEqual(
            'SoftLayer_Resource_Configuration/setOsPasswordFromEncrypted',
            response)

    def test_get_endpoint(self):
        meta_data = {"endpoint_url": "test"}
        self._service._get_endpoint(meta_data)
        self.assertEqual(meta_data.get("endpoint_url"), self._service._base_url)

    @mock.patch('bluemix.bluemixservice.BluemixService._get_meta_data')
    @mock.patch('bluemix.bluemixservice.BluemixService._get_endpoint')
    def test_can_post_password(self, mock_get_meta_data, mock_get_endpoint):
        self.assertTrue(self._service.can_post_password)
        mock_get_endpoint.assert_called_once()
        mock_get_meta_data.side_effect = base.NotExistingMetadataException
        self.assertFalse(self._service.can_post_password)


    @mock.patch('bluemix.bluemixservice.BluemixService._get_password_path')
    @mock.patch('bluemix.bluemixservice.BluemixService._post_data')
    @mock.patch('bluemix.bluemixservice.BluemixService._exec_with_retry')
    def _test_post_password(self, mock_exec_with_retry, mock_post_data,
                            mock_get_password_path, ret_val):
        mock_exec_with_retry.side_effect = [ret_val]
        if isinstance(ret_val, error.HTTPError):
            self.assertRaises(error.HTTPError,
                              self._service.post_password, 'fake')
        else:
            response = self._service.post_password(
                enc_password_b64='fake')
            mock_get_password_path.assert_called_once_with()
            self.assertEqual(ret_val, response)

    def test_post_password(self):
        self._test_post_password(ret_val='fake return')

    def test_post_password_other_HTTPError(self):
        err = error.HTTPError("https://api.service.softlayer.com/rest/v3.1/",
                              404, 'test error 404', {}, None)
        self._test_post_password(ret_val=err)

    @mock.patch('bluemix.bluemixservice.BluemixService'
                '._configure_headers_from_metadata')
    @mock.patch('bluemix.bluemixservice.BluemixService._http_request')
    def test_post_data(self, mock_http_request, mock_headers):
        fake_path = os.path.join('fake', 'path')
        fake_data = 'fake data'.encode()
        mock_data = mock.MagicMock()
        mock_http_request.return_value = mock_data
        mock_headers.return_value = 'fake headers'

        response = self._service._post_data(fake_path, fake_data)
        mock_http_request.assert_called_once_with(
            fake_path,
            data='{"parameters": ["fake data"]}',
            headers=mock_headers.return_value)
        self.assertTrue(response)

    @mock.patch('bluemix.bluemixservice.BluemixService._get_meta_data')
    def test_configure_headers_from_metadata(self, mock_get_meta_data):
        mock_get_meta_data.return_value = {"configuration_token": "token"}
        response = self._service._configure_headers_from_metadata()
        self.assertEqual({'Authorization': 'Bearer token'}, response)

    @mock.patch('bluemix.bluemixservice.BluemixService._get_meta_data')
    @mock.patch('cloudbaseinit.metadata.services.baseopenstackservice'
                '.BaseOpenStackService.get_public_keys')
    def test_get_public_keys(self, mock_public_keys, mock_get_meta_data):
        mock_public_keys.return_value = ["fake key"]
        mock_get_meta_data.return_value = {"crypt_key": "bluemix key"}

        response = self._service.get_public_keys()
        self.assertEqual('bluemix key', response[0])

    def test_get_dns_nameservers(self):
        network_data = {
            'services': [
                {'type': 'dns', 'address': '192.168.1.10'},
                {'type': 'dns', 'address': '192.168.1.11'},
            ]
        }
        response = self._service._get_dns_nameservers(network_data)
        self.assertEqual('192.168.1.10', response[0])
        self.assertEqual('192.168.1.11', response[1])

    @mock.patch('bluemix.bluemixservice.BluemixService'
                '._ipv6_netmask_to_prefix')
    def test_set_ipv6_network_details(self, mock_ipv6_netmask_to_prefix):
        network = {
            'ip_address': '0:0:0:0:0:ffff:c0a8:102',
            'netmask': '0:0:0:0:0:ffff:ffff:ff00',
            'routes': [
                {
                    'network': '::',
                    'netmask': '::',
                    'gateway': '0:0:0:0:0:ffff:c0a8:101'
                }
            ]
        }

        mock_ipv6_netmask_to_prefix.return_value = 64

        nic = mock.MagicMock()
        self._service._set_ipv6_network_details(network, nic)
        mock_ipv6_netmask_to_prefix.assert_called_once()

        self.assertEqual('0:0:0:0:0:ffff:c0a8:102', nic.address6)
        self.assertEqual(64, nic.netmask6)
        self.assertEqual('0:0:0:0:0:ffff:c0a8:101', nic.gateway6)

    @mock.patch('netaddr.IPAddress.is_netmask')
    @mock.patch('netaddr.IPAddress.netmask_bits')
    def test_ipv6_netmask_to_prefix(self, mock_netmask_bits, mock_is_netmask):
        mock_is_netmask.return_value = True
        mock_netmask_bits.return_value = 64

        self._service._ipv6_netmask_to_prefix(
            "ffff:ffff:ffff:ffff:0000:0000:0000:0000")
        mock_is_netmask.assert_called_once()
        mock_netmask_bits.assert_called_once()

    @mock.patch('netaddr.IPAddress.is_netmask')
    @mock.patch('netaddr.IPAddress.netmask_bits')
    def test_ipv6_netmask_to_prefix_invalid_netmask(self, mock_netmask_bits, mock_is_netmask):
        mock_is_netmask.return_value = False
        mock_netmask_bits.return_value = False

        self._service._ipv6_netmask_to_prefix(
            "ffff:ffff:ffff:ffff:0000:0000:0000:0000")
        mock_is_netmask.assert_called_once()
        mock_netmask_bits.assert_not_called()

    def test_set_ipv4_network_details(self):
        network = {
            'ip_address': '192.168.1.2',
            'netmask': '255.255.255.0',
            'routes': [
                {
                    'network': '0.0.0.0',
                    'netmask': '0.0.0.0',
                    'gateway': '192.168.1.1'
                }
            ]
        }
        nic = mock.MagicMock()
        self._service._set_ipv4_network_details(network, nic)
        self.assertEqual('192.168.1.2', nic.address)
        self.assertEqual('255.255.255.0', nic.netmask)
        self.assertEqual('192.168.1.1', nic.gateway)

    @mock.patch('bluemix.bluemixservice.BluemixService'
                '._set_ipv6_network_details')
    @mock.patch('bluemix.bluemixservice.BluemixService'
                '._set_ipv4_network_details')
    @mock.patch('bluemix.bluemixservice.BluemixService._get_dns_nameservers')
    @mock.patch('bluemix.bluemixservice.BluemixService._get_network_data')
    def test_convert_network_data(self, mock_get_network_data,
                                  mock_get_dns_nameservers,
                                  mock_set_ipv4_network_details,
                                  mock_set_ipv6_network_details):
        network_data = {
            'links': [
                {
                    "id": "interface_999999",
                    "name": "eth0",
                    "ethernet_mac_address": "0a:0b:0c:0d:0e:0f"
                },
                {
                    "id": "interface_888888",
                    "name": "eth1",
                    "ethernet_mac_address": "0f:0e:0d:0c:0b:0a"
                }
            ],
            'networks': [
                {
                    "id": "network_999999",
                    "link": "interface_999999",
                    "type": "ipv4",
                    "ip_address": "192.168.1.2",
                    "netmask": "255.255.255.0"
                },
                {
                    "id": "network_888888",
                    "link": "interface_999999",
                    "type": "ipv6",
                    "ip_address": "0:0:0:0:0:ffff:c0a8:102",
                    "netmask": "ffff:ffff:ffff:ffff:0000:0000:0000:0000"
                }
            ]
        }

        mock_get_network_data.return_value = network_data
        response = self._service._convert_network_data()
        self.assertEqual('eth0', response[0].name)
        self.assertEqual('0A:0B:0C:0D:0E:0F', response[0].mac)
        self.assertEqual('eth1', response[1].name)
        self.assertEqual('0F:0E:0D:0C:0B:0A', response[1].mac)
        mock_set_ipv4_network_details.assert_called_once()
        mock_set_ipv6_network_details.assert_called_once()

    @mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
    def _test_delete_static_route(self, mock_get_os_utils, err=None):
        network = '192.168.1.0'

        mock_os_utils = mock.MagicMock()
        mock_os_utils.execute_process.return_value = (True, err, None)
        mock_get_os_utils.return_value = mock_os_utils
        self._service._delete_static_route('192.168.1.0')

        mock_os_utils.execute_process.assert_called_once_with(
            ['ROUTE', 'DELETE', network])

    def test_delete_static_route(self):
        self._test_delete_static_route()

    def test_delete_static_route_error(self):
        self._test_delete_static_route(err='ERROR')

    @mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
    def _test_check_existing_route_matches(self, mock_get_os_utils, network,
                                           netmask, gateway):
        mock_os_utils = mock.MagicMock()
        mock_os_utils._get_ipv4_routing_table.return_value = \
            [['192.168.1.0', '255.255.255.0', '192.168.1.1']]
        mock_get_os_utils.return_value = mock_os_utils

        return self._service._check_existing_route_matches(network=network,
                                                           netmask=netmask,
                                                           gateway=gateway)

    def test_check_existing_route_matches(self):
        network = '192.168.1.0'
        netmask = '255.255.255.0'
        gateway = '192.168.1.1'
        self.assertTrue(self._test_check_existing_route_matches(
            network=network, netmask=netmask, gateway=gateway))

        network = '192.168.1.1'
        netmask = '255.255.255.0'
        gateway = '192.168.1.1'
        self.assertFalse(self._test_check_existing_route_matches(
            network=network, netmask=netmask, gateway=gateway))

        network = '192.168.1.0'
        netmask = '255.255.255.1'
        gateway = '192.168.1.1'
        self.assertFalse(self._test_check_existing_route_matches(
            network=network, netmask=netmask, gateway=gateway))

        network = '192.168.1.0'
        netmask = '255.255.255.0'
        gateway = '192.168.1.2'
        self.assertFalse(self._test_check_existing_route_matches(
            network=network, netmask=netmask, gateway=gateway))

    @mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
    def _test_add_persistent_route(self, mock_get_os_utils, err=None):
        network = '192.168.1.0'
        netmask = '255.255.255.0'
        gateway = '192.168.1.1'

        mock_os_utils = mock.MagicMock()
        mock_os_utils.execute_process.return_value = (True, err, None)

        mock_get_os_utils.return_value = mock_os_utils
        self._service._add_persistent_route(network=network,
                                            netmask=netmask,
                                            gateway=gateway)

        mock_os_utils.execute_process.assert_called_once_with(
            ['ROUTE', '-P', 'ADD', network, 'MASK', netmask, gateway,
             'METRIC', '1'])

    def test_add_persistent_route(self):
        self._test_add_persistent_route()

    def test_add_persistent_route_error(self):
        self._test_add_persistent_route(err='ERROR')

    @mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
    @mock.patch('bluemix.bluemixservice.BluemixService._add_persistent_route')
    @mock.patch('bluemix.bluemixservice.BluemixService._delete_static_route')
    @mock.patch('bluemix.bluemixservice.BluemixService'
                '._check_existing_route_matches')
    @mock.patch('bluemix.bluemixservice.BluemixService._get_persistent_routes')
    def test_check_persistent_routes(self, mock_get_persistent_routes,
                                     mock_check_existing_route_matches,
                                     mock_delete_static_route,
                                     mock_add_persistent_route,
                                     mock_get_os_utils):
        routes = [
            {
                "network": "192.168.0.0",
                "netmask": "255.255.0.0",
                "gateway": "192.168.0.12"
            }
        ]

        mock_osutil = mock.MagicMock()

        mock_osutil.check_static_route_exists.return_value = True
        mock_get_persistent_routes.return_value = routes
        mock_check_existing_route_matches.return_value = False
        mock_get_os_utils.return_value = mock_osutil

        response = self._service._check_persistent_routes()

        mock_get_persistent_routes.assert_called_once_with()
        mock_get_os_utils.assert_called_once_with()
        mock_osutil.check_static_route_exists.assert_called_once_with(
            '192.168.0.0')
        mock_check_existing_route_matches.assert_called_once_with(
            '192.168.0.0', '255.255.0.0', '192.168.0.12')
        mock_delete_static_route.assert_called_once_with(
            '192.168.0.0')
        mock_add_persistent_route.assert_called_once_with(
            '192.168.0.0', '255.255.0.0', '192.168.0.12')

    @mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
    @mock.patch('bluemix.bluemixservice.BluemixService._add_persistent_route')
    @mock.patch('bluemix.bluemixservice.BluemixService._delete_static_route')
    @mock.patch('bluemix.bluemixservice.BluemixService'
                '._check_existing_route_matches')
    @mock.patch('bluemix.bluemixservice.BluemixService._get_persistent_routes')
    def test_check_persistent_routes_existing_route(
            self,
            mock_get_persistent_routes,
            mock_check_existing_route_matches,
            mock_delete_static_route,
            mock_add_persistent_route,
            mock_get_os_utils):
        routes = [
            {
                "network": "192.168.0.0",
                "netmask": "255.255.0.0",
                "gateway": "192.168.0.12"
            }
        ]

        mock_osutil = mock.MagicMock()

        mock_osutil.check_static_route_exists.return_value = True
        mock_get_persistent_routes.return_value = routes
        mock_check_existing_route_matches.return_value = True
        mock_get_os_utils.return_value = mock_osutil

        response = self._service._check_persistent_routes()

        mock_get_persistent_routes.assert_called_once_with()
        mock_get_os_utils.assert_called_once_with()
        mock_osutil.check_static_route_exists.assert_called_once_with(
            '192.168.0.0')
        mock_check_existing_route_matches.assert_called_once_with(
            '192.168.0.0', '255.255.0.0', '192.168.0.12')
        mock_delete_static_route.assert_not_called()
        mock_add_persistent_route.assert_not_called()

    @mock.patch('bluemix.bluemixservice.BluemixService._get_persistent_routes')
    def test_check_persistent_routes_empty_routes(self,
                                                  mock_get_persistent_routes):
        routes = {}
        mock_get_persistent_routes.return_value = routes

        response = self._service._check_persistent_routes()
        mock_get_persistent_routes.assert_called_once_with()

        self.assertIsNone(response)

    @mock.patch('bluemix.bluemixservice.BluemixService._get_network_data')
    def test_get_persistent_routes(self, mock_get_network_data):
        network_data = {
            "networks": [
                {
                    "id": "network_2",
                    "type": "ipv6",
                    "routes": [
                        {
                            "network": "0:0:0:0:0:ffff:c0a8:102",
                            "netmask": "0:0:0:0:0:ffff:ffff:ff00",
                            "gateway": "0:0:0:0:0:ffff:c0a8:101"
                        }
                    ]
                },
                {
                    "id": "network_1",
                    "type": "ipv4",
                    "routes": [
                        {
                            "network": "10.0.0.0",
                            "netmask": "255.0.0.0",
                            "gateway": "192.168.0.11"
                        },
                        {
                            "network": "192.168.0.0",
                            "netmask": "255.255.0.0",
                            "gateway": "192.168.0.12"
                        }
                    ]
                }
            ]
        }

        mock_get_network_data.return_value = network_data

        response = self._service._get_persistent_routes()
        mock_get_network_data.assert_called_once_with()

        self.assertEqual('10.0.0.0', response[0].get('network'))
        self.assertEqual('255.0.0.0', response[0].get('netmask'))
        self.assertEqual('192.168.0.11', response[0].get('gateway'))
        self.assertEqual('192.168.0.0', response[1].get('network'))
        self.assertEqual('255.255.0.0', response[1].get('netmask'))
        self.assertEqual('192.168.0.12', response[1].get('gateway'))

    @mock.patch('bluemix.bluemixservice.BluemixService._get_meta_data')
    def test_get_kms_host(self, mock_get_meta_data):
        mock_get_meta_data.return_value = {"kms_host": "test"}
        kms_host = self._service.get_kms_host()
        self.assertEqual(kms_host, "test")

    @mock.patch('bluemix.bluemixservice.BluemixService._get_meta_data')
    def test_get_kms_host_no_endpoint(self, mock_get_meta_data):
        mock_get_meta_data.return_value = {"enpoint_url": "test"}
        kms_host = self._service.get_kms_host()
        self.assertEqual(kms_host, None)
