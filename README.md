# Bluemix Metadata Service For Cloudbase-init

## Install
Install the latest stable release as a python package using Windows PowerShell
```
& 'C:\Program Files\Cloudbase Solutions\Cloudbase-Init\Python\python.exe' -m pip install https://github.com/softlayer/bluemix-cloudbase-init/archive/master.zip
```

## Usage
Update the metadata_services config value in cloudbase-init-unattend.conf and cloudbase-init.conf to use the Bluemix metadata service
```
metadata_services=bluemix.bluemixservice.BluemixService,
```