#!/usr/bin/python
#
# Copyright (c) 2020 XiuxiSun, (@Fred-sun)
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
from email.policy import default
__metaclass__ = type


DOCUMENTATION = '''
---
module: azure_rm_virtualhub
version_added: '1.10.0'
short_description: Manage Azure VirtualHub instance
description:
    - Create, update and delete instance of Azure VirtualHub.
options:
    resource_group:
        description:
            - The resource group name of the VirtualHub.
        required: true
        type: str
    name:
        description:
            - The name of the VirtualHub.
        required: true
        type: str
    virtual_wan:
        description:
            - The VirtualWAN to which the VirtualHub belongs.
        type: dict
        suboptions:
            id:
                description:
                    - Resource ID.
                type: str
    vpn_gateway:
        description:
            - The VpnGateway associated with this VirtualHub.
        type: dict
        suboptions:
            id:
                description:
                    - Resource ID.
                type: str
    p2_s_vpn_gateway:
        description:
            - The P2SVpnGateway associated with this VirtualHub.
        type: dict
        suboptions:
            id:
                description:
                    - Resource ID.
                type: str
    express_route_gateway:
        description:
            - The expressRouteGateway associated with this VirtualHub.
        type: dict
        suboptions:
            id:
                description:
                    - Resource ID.
                type: str
    azure_firewall:
        description:
            - The azureFirewall associated with this VirtualHub.
        type: dict
        suboptions:
            id:
                description:
                    - Resource ID.
                type: str
    security_partner_provider:
        description:
            - The securityPartnerProvider associated with this VirtualHub.
        type: dict
        suboptions:
            id:
                description:
                    - Resource ID.
                type: str
    address_prefix:
        description:
            - Address-prefix for this VirtualHub.
        type: str
    route_table:
        description:
            - The routeTable associated with this virtual hub.
        type: dict
        suboptions:
            routes:
                description:
                    - List of all routes.
                elements: dict
                type: list
                suboptions:
                    address_prefixes:
                        description:
                            - List of all addressPrefixes.
                        type: list
                        elements: str
                    next_hop_ip_address:
                        description:
                            - NextHop ip address.
                        type: str
    security_provider_name:
        description:
            - The Security Provider name.
        type: str
    virtual_hub_route_table_v2_s:
        description:
            - List of all virtual hub route table v2s associated with this VirtualHub.
        type: list
        elements: dict
        suboptions:
            name:
                description:
                    - The name of the resource that is unique within a resource group.
                    - This name can be used to access the resource.
                type: str
            routes:
                description:
                    - List of all routes.
                type: list
                elements: dict
                suboptions:
                    destination_type:
                        description:
                            - The type of destinations.
                        type: str
                    destinations:
                        description:
                            - List of all destinations.
                        type: list
                        elements: str
                    next_hop_type:
                        description:
                            - The type of next hops.
                        type: str
                    next_hops:
                        description:
                            - NextHops ip address.
                        type: list
                        elements: str
            attached_connections:
                description:
                    - List of all connections attached to this route table v2.
                elements: str
                type: list
    sku:
        description:
            - The sku of this VirtualHub.
        type: str
    bgp_connections:
        description:
            - List of references to Bgp Connections.
        type: list
        elements: dict
        suboptions:
            id:
                description:
                    - Resource ID.
                type: str
    ip_configurations:
        description:
            - List of references to IpConfigurations.
        type: list
        elements: dict
        suboptions:
            id:
                description:
                    - Resource ID.
                type: str
    virtual_router_asn:
        description:
            - VirtualRouter ASN.
        type: int
    virtual_router_ips:
        description:
            - VirtualRouter IPs.
        type: list
        elements: str
    enable_virtual_router_route_propogation:
        description:
            - Flag to control route propogation for VirtualRouter hub.
        type: bool
    state:
        description:
            - Assert the state of the VirtualHub.
            - Use C(present) to create or update an VirtualHub and C(absent) to delete it.
        default: present
        type: str
        choices:
            - absent
            - present
extends_documentation_fragment:
    - azure.azcollection.azure
    - azure.azcollection.azure_tags
author:
    - Fred-Sun (@Fred-Sun)
    - Haiyuan Zhang (@haiyuazhang)

'''

EXAMPLES = '''
    - name: Create a VirtualHub
      azure_rm_virtualhub:
        resource_group: myResourceGroup
        name: my_virtual_hub_name
        address_prefix: 10.2.0.0/24
        sku: Standard
        enable_virtual_router_route_propogation: false
        virtual_wan:
          id: /subscriptions/xxx-xxx/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualWans/fredwan

    - name: Delete VirtualHub
      azure_rm_virtualhub:
        resource_group: myResourceGroup
        name: my_virtual_hub_name
        state: absent
'''

RETURN = '''
state:
    description:
        - Current state of the virtual hub.
    type: complex
    returned: always
    contains:
        id:
            description:
                - Resource ID.
            returned: always
            type: str
            sample: /subscriptions/xxx-xxx/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualHubs/my_virtual_hub_name
        name:
            description:
                - Resource name.
            returned: always
            type: str
            sample: my_virtual_hub_name
        type:
            description:
                - Resource type.
            returned: always
            type: str
            sample: Microsoft.Network/virtualHubs
        tags:
            description:
                - Resource tags.
            returned: always
            type: dict
            sample: { 'key1': 'value1' }
        etag:
            description:
                - A unique read-only string that changes whenever the resource is updated.
            returned: always
            type: str
            sample: cf8c0b06-d339-4155-95fd-2a363945cce4
        virtual_wan:
            description:
                - The VirtualWAN to which the VirtualHub belongs.
            returned: always
            type: complex
            contains:
                id:
                    description:
                        - Resource ID.
                    returned: always
                    type: str
                    sample: /subscriptions/xxx-xxx/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualWans/fredwan
        vpn_gateway:
            description:
                - The VpnGateway associated with this VirtualHub.
            returned: always
            type: complex
            contains:
                id:
                    description:
                        - Resource ID.
                    returned: always
                    type: str
                    sample: null
        p2_s_vpn_gateway:
            description:
                - The P2SVpnGateway associated with this VirtualHub.
            returned: always
            type: complex
            contains:
                id:
                    description:
                        - Resource ID.
                    returned: always
                    type: str
                    sample: null
        express_route_gateway:
            description:
                - The expressRouteGateway associated with this VirtualHub.
            returned: always
            type: dict
            sample: null
            contains:
                id:
                    description:
                        - Resource ID.
                    returned: always
                    type: str
                    sample: null
        azure_firewall:
            description:
                - The azureFirewall associated with this VirtualHub.
            returned: always
            type: complex
            contains:
                id:
                    description:
                        - Resource ID.
                    returned: always
                    type: str
                    sample: null
        security_partner_provider:
            description:
                - The securityPartnerProvider associated with this VirtualHub.
            returned: always
            type: complex
            contains:
                id:
                    description:
                        - Resource ID.
                    returned: always
                    type: str
                    sample: null
        address_prefix:
            description:
                - Address-prefix for this VirtualHub.
            returned: always
            type: str
            sample: 10.2.0.0/24
        route_table:
            description:
                - The routeTable associated with this virtual hub.
            returned: always
            type: complex
            contains:
                routes:
                    description:
                        - List of all routes.
                    returned: always
                    type: list
                    contains:
                        address_prefixes:
                            description:
                                - List of all addressPrefixes.
                            returned: always
                            type: list
                            sample: null
                        next_hop_ip_address:
                            description:
                                - NextHop ip address.
                            returned: always
                            type: str
                            sample: null
        provisioning_state:
            description:
                - The provisioning state of the virtual hub resource.
            returned: always
            type: str
            sample: Succeeded
        security_provider_name:
            description:
                - The Security Provider name.
            returned: always
            type: str
            sample: null
        virtual_hub_route_table_v2_s:
            description:
                - List of all virtual hub route table v2s associated with this VirtualHub.
            returned: always
            type: complex
            contains:
                name:
                    description:
                        - The name of the resource that is unique within a resource group.
                        - This name can be used to access the resource.
                    returned: always
                    type: str
                    sample: null
                routes:
                    description:
                        - List of all routes.
                    returned: always
                    type: list
                    contains:
                        destination_type:
                            description:
                                - The type of destinations.
                            returned: always
                            type: str
                            sample: null
                        destinations:
                            description:
                                - List of all destinations.
                            returned: always
                            type: list
                            sample: null
                        next_hop_type:
                            description:
                                - The type of next hops.
                            returned: always
                            type: str
                            sample: null
                        next_hops:
                            description:
                                - NextHops ip address.
                            returned: always
                            type: list
                            sample: null
                attached_connections:
                    description:
                        - List of all connections attached to this route table v2.
                    returned: always
                    type: list
                    sample: null
        sku:
            description:
                - The sku of this VirtualHub.
            returned: always
            type: str
            sample: null
        routing_state:
            description:
                - The routing state.
            returned: always
            type: str
            sample: Standard
        bgp_connections:
            description:
                - List of references to Bgp Connections.
            returned: always
            type: list
            contains:
                id:
                    description:
                        - Resource ID.
                    returned: always
                    type: str
                    sample: null
        ip_configurations:
            description:
                - List of references to IpConfigurations.
            returned: always
            type: list
            contains:
                id:
                    description:
                        - Resource ID.
                    returned: always
                    type: str
                    sample: null
        virtual_router_asn:
            description:
                - VirtualRouter ASN.
            returned: always
            type: int
            sample: null
        virtual_router_ips:
            description:
                - VirtualRouter IPs.
            returned: always
            type: list
            sample: null
        enable_virtual_router_route_propogation:
            description:
                - Flag to control route propogation for VirtualRouter hub.
            returned: always
            type: bool
            sample: null

'''

from ansible_collections.azure.azcollection.plugins.module_utils.azure_rm_common_ext import AzureRMModuleBaseExt
try:
    from msrestazure.azure_exceptions import CloudError
    from msrestazure.azure_operation import AzureOperationPoller
    from msrest.polling import LROPoller
except ImportError:
    # This is handled in azure_rm_common
    pass


class Actions:
    NoAction, Create, Update, Delete = range(4)


propagated_route_tables_spec = dict(
    labels=dict(type='list', elements='str'),
    ids=dict(type='list', elements='str'),
)

routing_configuration_spec = dict(
    associated_route_table=dict(type='str', required=True),
    propagated_route_tables=dict(type='dict', options=propagated_route_tables_spec),
)

class AzureRMVirtualHubConnection(AzureRMModuleBaseExt):
    def __init__(self):
        self.module_arg_spec = dict(
            resource_group=dict(
                type='str',
                required=True
            ),
            hub_name=dict(
                type='str',
                required=True
            ),
            name=dict(
                type='str'
            ),
            remote_virtual_network=dict(
                type='dict',
                options=dict(
                    subscription_id=dict(
                        type='str'
                    ),
                    resource_group=dict(
                        type='str'
                    ),
                    name=dict(
                        type='str',
                        required=True
                    )
                )
            ),
            allow_hub_to_remote_vnet_transit=dict(
                type='bool',
                default=True
            ),
            allow_remote_vnet_to_use_hub_vnet_gateways=dict(
                type='bool',
                default=True
            ),
            enable_internet_security=dict(
                type='bool',
                default=False
            ),
            routing_configuration=dict(
                type='dict', 
                options=routing_configuration_spec
            ),
            state=dict(
                type='str',
                default='present',
                choices=['present', 'absent']
            )
        )

        self.resource_group = None
        self.hub_name = None
        self.name = None
        self.body = {}

        self.results = dict(changed=False)
        self.state = None
        self.to_do = Actions.NoAction

        super(AzureRMVirtualHubConnection, self).__init__(derived_arg_spec=self.module_arg_spec,
                                                supports_check_mode=True,
                                                supports_tags=True)

    def exec_module(self, **kwargs):
        for key in list(self.module_arg_spec.keys()):
            if hasattr(self, key):
                setattr(self, key, kwargs[key])
            elif kwargs[key] is not None:
                self.body[key] = kwargs[key]

        self.inflate_parameters(self.module_arg_spec, self.body, 0)

        #resource_group = self.get_resource_group(self.resource_group)

        old_response = None
        response = None

        old_response = self.get_resource()

        if 'remote_virtual_network' in self.body:
            self.body['remote_virtual_network'] = dict(
                id=vnet_id(
                    self.body['remote_virtual_network']['subscription_id'] or self.subscription_id,
                    self.body['remote_virtual_network']['resource_group'] or self.resource_group,
                    self.body['remote_virtual_network']['name']
                )
            )

        if 'routing_configuration' in self.body:
            routing_configuration = self.body['routing_configuration']
            self.body['routing_configuration'] = dict(
                associated_route_table=dict(
                    id=routetable_id(
                        self.subscription_id,
                        self.resource_group,
                        self.hub_name,
                        routing_configuration['associated_route_table']
                    )
                ),
                propagated_route_tables=dict(
                    labels=routing_configuration['propagated_route_tables']['labels'],
                    ids=[dict(
                            id=routetable_id(
                                self.subscription_id,
                                self.resource_group,
                                self.hub_name,
                                item
                            )
                        ) for item in routing_configuration['propagated_route_tables']['ids']] if routing_configuration['propagated_route_tables']['ids'] else None
                )
            )


        if not old_response:
            if self.state == 'present':
                self.to_do = Actions.Create
        else:
            if self.state == 'absent':
                self.to_do = Actions.Delete
            else:
                modifiers = {}
                self.create_compare_modifiers(self.module_arg_spec, '', modifiers)
                self.results['modifiers'] = modifiers
                self.results['compare'] = []
                if not self.default_compare(modifiers, self.body, old_response, '', self.results):
                    self.to_do = Actions.Update

        if (self.to_do == Actions.Create) or (self.to_do == Actions.Update):
            self.results['changed'] = True
            if self.check_mode:
                return self.results
            response = self.create_update_resource()
        elif self.to_do == Actions.Delete:
            self.results['changed'] = True
            if self.check_mode:
                return self.results
            self.delete_resource()
        else:
            self.results['changed'] = False
            response = old_response

        if response is not None:
            self.results['state'] = response

        return self.results

    def create_update_resource(self):
        try:
            response = self.network_client.hub_virtual_network_connections.create_or_update(resource_group_name=self.resource_group,
                                                                         virtual_hub_name=self.hub_name,
                                                                         connection_name=self.name,
                                                                         hub_virtual_network_connection_parameters=self.body)
            if isinstance(response, AzureOperationPoller) or isinstance(response, LROPoller):
                response = self.get_poller_result(response)
        except CloudError as exc:
            self.log('Error attempting to create the VirtualHub instance.')
            self.fail('Error creating the VirtualHub instance: {0}'.format(str(exc)))
        return response.as_dict()

    def delete_resource(self):
        try:
            response = self.network_client.hub_virtual_network_connections.delete(resource_group_name=self.resource_group,
                                                                                    virtual_hub_name=self.hub_name,
                                                                                    connection_name=self.name)
        except CloudError as e:
            self.log('Error attempting to delete the VirtualHub instance.')
            self.fail('Error deleting the VirtualHub instance: {0}'.format(str(e)))

        return True

    def get_resource(self):
        try:
            response = self.network_client.hub_virtual_network_connections.get(resource_group_name=self.resource_group,
                                                                                virtual_hub_name=self.hub_name,
                                                                                connection_name=self.name)
        except CloudError as e:
            return False
        return response.as_dict()

def vnet_id(subscription_id, resource_group_name, virtual_network_name):
    """Generate the id for a virtual network"""
    return '/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Network/virtualNetworks/{2}'.format(
        subscription_id,
        resource_group_name,
        virtual_network_name
    )

def routetable_id(subscription_id, resource_group_name, virtual_hub_name, route_table_name):
    """Generate the id for a virtual network"""
    #"/subscriptions/04ae2105-744b-409d-89aa-c67c328de4ff/resourceGroups/rg-vwan-msssdmz/providers/Microsoft.Network/virtualHubs/MSSS-DMZ/hubRouteTables/defaultRouteTable"
    return '/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Network/virtualHubs/{2}/hubRouteTables/{3}'.format(
        subscription_id,
        resource_group_name,
        virtual_hub_name,
        route_table_name
    )

def main():
    AzureRMVirtualHubConnection()


if __name__ == '__main__':
    main()
