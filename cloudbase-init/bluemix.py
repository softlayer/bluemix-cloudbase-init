import os
import shutil
import re

from oslo_config import cfg
from oslo_log import log as oslo_logging

from cloudbaseinit import exception
from cloudbaseinit.metadata.services import base
from cloudbaseinit.metadata.services import baseopenstackservice
from cloudbaseinit.metadata.services.osconfigdrive import factory
from cloudbaseinit.osutils import factory as osutils_factory
from cloudbaseinit.osutils.windows import WindowsUtils
from cloudbaseinit.utils import encoding

CD_TYPES = {"vfat"}
CD_LOCATIONS = {"partition"}

LOG = oslo_logging.getLogger(__name__)


class BluemixService(baseopenstackservice.BaseOpenStackService):

    def __init__(self):
        super(BluemixService, self).__init__()
        self._metadata_path = None

    def load(self):
        super(BluemixService, self).load()

        self._searched_types = set(CD_TYPES)
        self._searched_locations = set(CD_LOCATIONS)

        self._mgr = factory.get_config_drive_manager()
        found = self._mgr.get_config_drive_files(
            searched_types=self._searched_types,
            searched_locations=self._searched_locations)

        if found:
            self._metadata_path = self._mgr.target_path
            LOG.debug('Metadata copied to folder: %r', self._metadata_path)
        return found

    def get_network_details(self):
        self._check_persistent_routes()
        return super(BluemixService, self).get_network_details()

    def _get_data(self, path):
        norm_path = os.path.normpath(os.path.join(self._metadata_path, path))
        try:
            with open(norm_path, 'rb') as stream:
                return stream.read()
        except IOError:
            raise base.NotExistingMetadataException()

    def _get_persistent_routes(self):
        """Parses network_config for persistent static routes."""
        routes = []
        network_config = self._get_meta_data().get('network_config')
        if not network_config:
            return routes
        key = "content_path"
        if key not in network_config:
            return routes
        content_name = network_config[key].rsplit("/", 1)[-1]
        content = self.get_content(content_name)
        content = encoding.get_as_string(content)
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            regex = re.compile(r"post-up route add -net (?P<{}>[^/]+) "
                               r"netmask (?P<{}>[^/]+) gw (?P<{}>[^/]+)"
                               .format('network', 'netmask', 'gateway'))
            match = regex.match(line)
            if match:
                routes.append(match.groupdict())

        return routes

    def _check_persistent_routes(self):
        """Verify required persistent routes exist on operating system."""
        routes = self._get_persistent_routes()
        if not routes:
            return None

        osutils = osutils_factory.get_os_utils()
        for route in routes:
            if osutils.check_static_route_exists(route.get('network')):
                if not self._check_existing_route_matches(route.get('network'),
                                       route.get('netmask'),
                                       route.get('gateway')):
                    self._delete_static_route(route.get('network'))
                else:
                    continue

            self._add_persistent_route(route.get('network'),
                                       route.get('netmask'),
                                       route.get('gateway'));

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
        osutils = osutils_factory.get_os_utils()
        return len([r for r in osutils._get_ipv4_routing_table()
                    if r[0] == network and r[1] == netmask 
                        and r[2] == gateway]) > 0

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

    def cleanup(self):
        LOG.debug('Deleting metadata folder: %r', self._mgr.target_path)
        shutil.rmtree(self._mgr.target_path, ignore_errors=True)
        self._metadata_path = None
