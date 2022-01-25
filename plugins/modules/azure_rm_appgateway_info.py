#!/usr/bin/python
#
# Copyright (c) 2021 Ross Bender (@l3ender)
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: azure_rm_appgateway_info
version_added: "1.10.0"
short_description: Retrieve Application Gateway instance facts
description:
    - Get facts for a Application Gateway instance.
options:
    name:
        description:
            - Only show results for a specific application gateway.
        type: str
    resource_group:
        description:
            - Limit results by resource group.
        type: str

extends_documentation_fragment:
    - azure.azcollection.azure

author:
    - Ross Bender (@l3ender)
'''

EXAMPLES = '''
    - name: Get facts for application gateway by name.
      azure_rm_appgateway_info:
        name: MyAppgw
        resource_group: MyResourceGroup

    - name: Get facts for application gateways in resource group.
      azure_rm_appgateway_info:
        resource_group: MyResourceGroup

    - name: Get facts for all application gateways.
      azure_rm_appgateway_info:
'''

RETURN = '''
gateways:
    description:
        - A list of dictionaries containing facts for an application gateway.
    returned: always
    type: complex
    contains:
        id:
            description:
                - Application gateway resource ID.
            returned: always
            type: str
            sample: /subscriptions/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/resourceGroups/myResourceGroup/providers/Microsoft.Network/applicationGateways/myAppGw
        name:
            description:
                - Name of application gateway.
            returned: always
            type: str
            sample: myAppGw
        resource_group:
            description:
                - Name of resource group.
            returned: always
            type: str
            sample: myResourceGroup
        location:
            description:
                - Location of application gateway.
            returned: always
            type: str
            sample: centralus
        operational_state:
            description:
                - Operating state of application gateway.
            returned: always
            type: str
            sample: Running
        provisioning_state:
            description:
                - Provisioning state of application gateway.
            returned: always
            type: str
            sample: Succeeded
'''

import re
from ansible_collections.azure.azcollection.plugins.module_utils.azure_rm_common import AzureRMModuleBase

try:
    from msrestazure.azure_exceptions import CloudError
    from azure.mgmt.network import NetworkManagementClient
    from msrestazure.tools import parse_resource_id
except ImportError:
    # This is handled in azure_rm_common
    pass


class AzureRMApplicationGatewayInfo(AzureRMModuleBase):

    def __init__(self):

        self.module_arg_spec = dict(
            name=dict(type='str'),
            resource_group=dict(type='str'),
        )

        self.results = dict(
            changed=False,
        )

        self.name = None
        self.resource_group = None
        self.mgmt_client = None

        super(AzureRMApplicationGatewayInfo, self).__init__(self.module_arg_spec,
                                                            supports_check_mode=True,
                                                            supports_tags=False,
                                                            facts_module=True)

    def exec_module(self, **kwargs):
        for key in self.module_arg_spec:
            setattr(self, key, kwargs[key])

        self.mgmt_client = self.get_mgmt_svc_client(NetworkManagementClient,
                                                    base_url=self._cloud_environment.endpoints.resource_manager)

        if self.name is not None:
            self.results["gateways"] = self.get()
        elif self.resource_group is not None:
            self.results["gateways"] = self.list_by_rg()
        else:
            self.results["gateways"] = self.list_all()

        return self.results

    def get(self):
        response = None
        results = []
        try:
            response = self.mgmt_client.application_gateways.get(resource_group_name=self.resource_group, application_gateway_name=self.name)
        except CloudError:
            pass

        if response is not None:
            results.append(self.format_response(response))

        return results

    def list_by_rg(self):
        response = None
        results = []
        try:
            response = self.mgmt_client.application_gateways.list(resource_group_name=self.resource_group)

        except CloudError as exc:
            request_id = exc.request_id if exc.request_id else ''
            self.fail("Error listing application gateways in resource groups {0}: {1} - {2}".format(self.resource_group, request_id, str(exc)))

        for item in response:
            results.append(self.format_response(item))

        return results

    def list_all(self):
        response = None
        results = []
        try:
            response = self.mgmt_client.application_gateways.list_all()
        except CloudError as exc:
            request_id = exc.request_id if exc.request_id else ''
            self.fail("Error listing all application gateways: {0} - {1}".format(request_id, str(exc)))

        for item in response:
            results.append(self.format_response(item))

        return results

    def format_response(self, appgw):
        d = appgw.as_dict()
        id = d.get("id")
        id_dict = parse_resource_id(id)
        d = {
            "id": id,
            "name": d.get("name"),
            "resource_group": id_dict.get('resource_group', self.resource_group),
            "location": d.get("location"),
            "operational_state": d.get("operational_state"),
            "provisioning_state": d.get("provisioning_state"),
            "private_ip_address": self.get_private_ip(appgw),
            "public_ip_address": self.get_public_ip(appgw)
        }
        return d

    def get_private_ip(self, response):
        self.log('Get private ip for {0}'.format(self.name))
        if response:
            frontend_ip_configurations = response.frontend_ip_configurations
            for item in frontend_ip_configurations:
                if item.private_ip_address:
                    return item.private_ip_address
        return None

    def get_public_ip(self, response):
        self.log('Get public ip for {0}'.format(self.name))
        if response:
            id = None
            frontend_ip_configurations = response.frontend_ip_configurations
            for item in frontend_ip_configurations:
                if item.public_ip_address:
                    match = re.search(r'([^/]+)/providers/Microsoft.Network/publicIPAddresses/([^/]+)$', item.public_ip_address.id)
                    resource_group = match.group(1)
                    id = match.group(2)
                    break
            try:
                if id:
                    item = self.network_client.public_ip_addresses.get(resource_group, id)
                    return item.ip_address
            except CloudError:
                pass
        return None

def main():
    AzureRMApplicationGatewayInfo()


if __name__ == '__main__':
    main()
