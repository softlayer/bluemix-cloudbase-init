from cloudinit import log as logging
from cloudinit import sources
from cloudinit.sources import DataSourceConfigDrive as configdrive

LOG = logging.getLogger(__name__)

class DataSourceBluemix(configdrive.DataSourceConfigDrive):
    def __init__(self, sys_cfg, distro, paths):
        super(DataSourceBluemix, self).__init__(sys_cfg, distro, paths)
        self.cfg = {}

    def get_data(self):
        response = super(DataSourceBluemix, self).get_data()
        if not response:
            return response

        password = self.metadata.get('encrypted_password')
        if password:
            LOG.debug("Retrieved encrypted password from metadata")
            self.cfg = {
                "users": [
                    "default",
                    {
                        "hashed_passwd": password
                    }
                ]
            }

        return response

    def get_config_obj(self):
        return self.cfg # Used to match classes to dependencies

# Used to match classes to dependencies
datasources = [
    (DataSourceBluemix, (sources.DEP_FILESYSTEM,)),
]

# Return a list of data sources that match this set of dependencies
def get_datasource_list(depends):
    return sources.list_from_depends(depends, datasources)

# vi: ts=4 expandtab