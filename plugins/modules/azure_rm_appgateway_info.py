#!/usr/bin/python
#
# Copyright (c) 2017 Zim Kalinowski, <zikalino@microsoft.com>
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: azure_rm_appgateway_info
version_added: "0.1.2"
short_description: Manage Application Gateway instance
description:
    - Create, update and delete instance of Application Gateway.

options:
    resource_group:
        description:
            - The name of the resource group.
        required: True
    name:
        description:
            - The name of the application gateway.
        required: True

extends_documentation_fragment:
    - azure.azcollection.azure
    - azure.azcollection.azure_tags

author:
    - Zim Kalinowski (@zikalino)

'''

EXAMPLES = '''
- name: Get info instance of Application Gateway
  azure_rm_appgateway_info:
    resource_group: myResourceGroup
    name: myAppGateway
    
'''

RETURN = '''
id:
    description:
        - Resource ID.
    returned: always
    type: str
    sample: id
'''

import time
from ansible_collections.azure.azcollection.plugins.module_utils.azure_rm_common import AzureRMModuleBase
from copy import deepcopy
from ansible.module_utils.common.dict_transformations import (
    camel_dict_to_snake_dict, snake_dict_to_camel_dict,
    _camel_to_snake, _snake_to_camel, dict_merge,
)

try:
    from msrestazure.azure_exceptions import CloudError
    from msrest.polling import LROPoller
    from azure.mgmt.network import NetworkManagementClient
    from msrest.serialization import Model
except ImportError:
    # This is handled in azure_rm_common
    pass


class Actions:
    NoAction, Create, Update, Delete = range(4)



class AzureRMApplicationGateways(AzureRMModuleBase):
    """Configuration class for an Azure RM Application Gateway resource"""

    def __init__(self):
        self.module_arg_spec = dict(
            resource_group=dict(
                type='str',
                required=True
            ),
            name=dict(
                type='str',
                required=True
            ),
        )

        self.resource_group = None
        self.name = None
        self.parameters = dict()

        self.results = dict(changed=False)
        self.mgmt_client = None
        self.to_do = Actions.NoAction

        super(AzureRMApplicationGateways, self).__init__(derived_arg_spec=self.module_arg_spec,
                                                         supports_check_mode=True,
                                                         supports_tags=True)

    def exec_module(self, **kwargs):
        """Main module execution method"""

        for key in list(self.module_arg_spec.keys()):
            if hasattr(self, key):
                setattr(self, key, kwargs[key])

        old_response = None
        response = None

        self.mgmt_client = self.get_mgmt_svc_client(NetworkManagementClient,
                                                    base_url=self._cloud_environment.endpoints.resource_manager)

        old_response = self.get_applicationgateway()
    
        self.log("Application Gateway instance unchanged")
        self.results['changed'] = False
        response = old_response
        self.results["gateway"] = {}
        self.results["private_ip_address"] = self.getPrivateIp(response)
        if response:
            response['backend_address_pools'] = len(response['backend_address_pools'])
            response['trusted_root_certificates'] = len(response['trusted_root_certificates'])
            response['ssl_certificates'] = len(response['ssl_certificates'])
            response['probes'] = len(response['probes'])
            response['backend_http_settings_collection'] = len(response['backend_http_settings_collection'])
            response['http_listeners'] = len(response['http_listeners'])
            response['url_path_maps'] = len(response['url_path_maps'])
            response['request_routing_rules'] = len(response['request_routing_rules'])
            response['rewrite_rule_sets'] = len(response['rewrite_rule_sets'])
            response['redirect_configurations'] = len(response['redirect_configurations'])
            response['custom_error_configurations'] = len(response['custom_error_configurations'])
            self.results["gateway"] = response

        return self.results

    def getPrivateIp(self, response):
        if response:
            frontend_ip_configurations = response['frontend_ip_configurations']
            for item in frontend_ip_configurations:
                if 'private_ip_address' in item:
                    return item['private_ip_address']
        return '0.0.0.0'

    def get_applicationgateway(self):
        '''
        Gets the properties of the specified Application Gateway.

        :return: deserialized Application Gateway instance state dictionary
        '''
        self.log("Checking if the Application Gateway instance {0} is present".format(self.name))
        found = False
        try:
            response = self.mgmt_client.application_gateways.get(resource_group_name=self.resource_group,
                                                                 application_gateway_name=self.name)
            found = True
            self.log("Response : {0}".format(response))
            self.log("Application Gateway instance : {0} found".format(response.name))
        except CloudError as e:
            self.log('Did not find the Application Gateway instance.')
        if found is True:
            return response.as_dict()

        return False


def main():
    """Main execution"""
    AzureRMApplicationGateways()


if __name__ == '__main__':
    main()
