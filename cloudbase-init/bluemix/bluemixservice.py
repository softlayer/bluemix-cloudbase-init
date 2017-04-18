import os
import shutil
import re
import requests
import json

from oslo_config import cfg
from oslo_log import log as oslo_logging
from six.moves.urllib import error

from cloudbaseinit import constant
from cloudbaseinit import exception
from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit.metadata.services import base
from cloudbaseinit.metadata.services import baseopenstackservice
from cloudbaseinit.metadata.services.osconfigdrive import factory
from cloudbaseinit.osutils import factory as osutils_factory
from cloudbaseinit.osutils.windows import WindowsUtils
from cloudbaseinit.utils import encoding

CONF = cloudbaseinit_conf.CONF
LOG = oslo_logging.getLogger(__name__)

CD_TYPES = constant.CD_TYPES
CD_LOCATIONS = constant.CD_LOCATIONS


class BluemixService(baseopenstackservice.BaseOpenStackService):
    _NETWORK_DATA_JSON = "openstack/latest/network_data.json"
    _DEFAULT_BASE_URL = "https://api.service.softlayer.com/rest/v3.1/"

    def __init__(self):
        super(BluemixService, self).__init__()
        self._metadata_path = None
        self._enable_retry = True

    def _preprocess_options(self):
        """Process which types and locations to search for metadata."""
        self._searched_types = set(CONF.config_drive.types)
        self._searched_locations = set(CONF.config_drive.locations)

        # Deprecation backward compatibility.
        if CONF.config_drive.raw_hdd:
            self._searched_types.add("iso")
            self._searched_locations.add("hdd")
        if CONF.config_drive.cdrom:
            self._searched_types.add("iso")
            self._searched_locations.add("cdrom")
        if CONF.config_drive.vfat:
            self._searched_types.add("vfat")
            self._searched_locations.add("hdd")

        # Check for invalid option values.
        if self._searched_types | CD_TYPES != CD_TYPES:
            raise exception.CloudbaseInitException(
                "Invalid Config Drive types %s", self._searched_types)
        if self._searched_locations | CD_LOCATIONS != CD_LOCATIONS:
            raise exception.CloudbaseInitException(
                "Invalid Config Drive locations %s", self._searched_locations)

    def load(self):
        super(BluemixService, self).load()

        self._preprocess_options()
        self._mgr = factory.get_config_drive_manager()
        found = self._mgr.get_config_drive_files(
            searched_types=self._searched_types,
            searched_locations=self._searched_locations)

        if found:
            self._metadata_path = self._mgr.target_path
            LOG.debug('Metadata copied to folder: %r', self._metadata_path)
        return found

    def get_network_details(self):
        """Parses through network data."""
        self._check_persistent_routes()
        return self._convert_network_data()

    def _get_network_data(self):
        """Grabs network_data to be parsed."""
        data = self._get_data(self._NETWORK_DATA_JSON)
        network_data = json.loads(encoding.get_as_string(data))

        return network_data

    def _get_data(self, path):
        """Used to read file from path string. NOTE: Not used for http data"""
        norm_path = os.path.normpath(os.path.join(self._metadata_path, path))
        try:
            with open(norm_path, 'rb') as stream:
                return stream.read()
        except IOError:
            raise base.NotExistingMetadataException()

    def _get_persistent_routes(self):
        """Parses network_data.json for persistent static routes."""
        network_data = self._get_network_data()
        routes_to_apply = []
        for network in network_data.get('networks', []):
            routes = network.get('routes', [])
            for route in routes:
                if route["network"] != "0.0.0.0" and route["network"] != '::':
                    routes_to_apply.append(route)
                    LOG.debug('Applying route: %s', route["network"])

        return routes_to_apply

    def _check_persistent_routes(self):
        """Verify required persistent routes exist on operating system."""
        routes = self._get_persistent_routes()
        if not routes:
            return None

        osutils = osutils_factory.get_os_utils()
        for route in routes:
            if osutils.check_static_route_exists(route.get('network')):
                if not self._check_existing_route_matches(
                        route.get('network'),
                        route.get('netmask'),
                        route.get('gateway')):
                    self._delete_static_route(route.get('network'))
                else:
                    continue

            self._add_persistent_route(
                route.get('network'),
                route.get('netmask'),
                route.get('gateway'))

    def _add_persistent_route(self, network, netmask, gateway):
        """Add a persistent route to the operating system."""
        try:
            osutils = osutils_factory.get_os_utils()
            LOG.debug('Adding route for network: %s', network)
            args = ['ROUTE', '-P', 'ADD', network, 'MASK',
                    netmask, gateway, 'METRIC', '1']
            (out, err, ret_val) = osutils.execute_process(args)
            if ret_val or err:
                raise exception.CloudbaseInitException(
                    'Unable to add route: %s' % err)
        except Exception as ex:
            LOG.exception(ex)

    def _check_existing_route_matches(self, network, netmask, gateway):
        """Check to make sure a route does not already exist in the ip table"""
        osutils = osutils_factory.get_os_utils()
        return len([r for r in osutils._get_ipv4_routing_table()
                    if r[0] == network and
                    r[1] == netmask and
                    r[2] == gateway]) > 0

    def _delete_static_route(self, network):
        """Delete a route from the operating system."""
        try:
            osutils = osutils_factory.get_os_utils()
            LOG.debug('Deleting route for network: %s', network)
            args = ['ROUTE', 'DELETE', network]
            (out, err, ret_val) = osutils.execute_process(args)
            if ret_val or err:
                raise exception.CloudbaseInitException(
                    'Failed to delete route: %s' % err)
        except Exception as ex:
            LOG.exception(ex)

    def _convert_network_data(self):
        """Parses network_data and converts to NetworkDetails namedtuple."""
        network_data = self._get_network_data()

        # Create a template because namedtuples are immutable
        nic_template = dict.fromkeys(base.NetworkDetails._fields)

        nics = []
        for link in network_data.get('links', []):
            nic = AttributeDict(nic_template)
            # Must make mac uppercase to match windows adapter mac.
            nic.mac = link["ethernet_mac_address"].upper()
            nic.name = link["name"]
            for network in network_data.get('networks', []):
                # Each link can have multiple networks for ipv4 and ipv6.
                # Skip if they don't match.
                if network["link"] != link["id"]:
                    continue
                if network["type"] == "ipv4":
                    self._set_ipv4_network_details(network, nic)
                elif network["type"] == "ipv6":
                    self._set_ipv6_network_details(network, nic)
            LOG.debug('Appending NetworkDetails object: %s', nic.mac)
            nics.append(base.NetworkDetails(**nic))
        return nics

    def _set_ipv4_network_details(self, network, nic):
        """Sets ipv4 information for NetworkDetails"""
        nic.address = network["ip_address"]
        nic.netmask = network["netmask"]
        for route in network.get('routes', []):
            if route["network"] == "0.0.0.0":
                nic.gateway = route["gateway"]

    def _set_ipv6_network_details(self, network, nic):
        """Sets ipv6 information for NetworkDetails"""
        nic.address6 = network["ip_address"]
        nic.netmask6 = network["netmask"]
        for route in network.get('routes', []):
            if route["network"] == "::":
                nic.gateway6 = route["gateway"]

    def get_public_keys(self):
        """Get a list of all unique public keys found among the metadata"""
        # Call the openstack service to get the normal list of public keys.
        public_keys = super(BluemixService, self).get_public_keys()
        # Add our key to list of metadata keys. Used to encrypt the password.
        meta_data = self._get_meta_data()
        crypt_key = meta_data.get("crypt_key").strip()
        public_keys.insert(0, crypt_key)

        return public_keys

    @property
    def can_post_password(self):
        """Called by the set user password plugin to allow service to post."""
        try:
            self._get_meta_data()
            return True
        except base.NotExistingMetadataException:
            return False

    def post_password(self, enc_password_b64):
        """Called by the set user password plugin to post the password."""
        try:
            path = self._get_password_path()
            action = lambda: self._post_data(path, enc_password_b64)
            return self._exec_with_retry(action)
        except error.HTTPError as ex:
            raise

    def _post_data(self, path, data):
        """Configures post data to be used in http request."""
        headers = self._configure_headers_from_metadata()
        # Have to decode the b64 encoded byte string for json serialization.
        json_data = {"parameters": [data.decode('utf-8')]}
        self._http_request(path, data=json.dumps(json_data), headers=headers)
        # return True here so that exec_with_retry knows to not retry anymore.
        return True

    def _http_request(self, url, data=None, headers=None):
        """Get content for received url."""
        if not url.startswith("http"):
            url = requests.compat.urljoin(self._DEFAULT_BASE_URL, url)
        request_action = requests.get if not data else requests.post
        if not data:
            LOG.debug('Getting metadata from: %s', url)
        else:
            LOG.debug('Posting data to %s', url)

        response = request_action(
            url=url,
            data=data,
            headers=headers,
            verify=False
        )
        response.raise_for_status()
        return response.content

    def _configure_headers_from_metadata(self):
        """Returns authorization token headers used for posting password"""
        meta_data = self._get_meta_data()

        config_token = meta_data.get('config_token')
        header_value = "Bearer " + config_token
        headers = {'Authorization': header_value}
        return headers

    def _get_password_path(self):
        """Returns the url used to post the password"""
        return 'SoftLayer_Resource_Configuration/setOsPasswordFromEncrypted'

    def cleanup(self):
        """Cleans up metadata path after completion"""
        LOG.debug('Deleting metadata folder: %r', self._mgr.target_path)
        shutil.rmtree(self._mgr.target_path, ignore_errors=True)
        self._metadata_path = None


class AttributeDict(dict):
    __getattr__ = dict.get
    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__
