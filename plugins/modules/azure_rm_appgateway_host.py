#!/usr/bin/python
#
# Copyright (c) 2017 Zim Kalinowski, <zikalino@microsoft.com>
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: azure_rm_appgateway_host
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
    redirect_configurations:
        description:
            - Redirect configurations of the application gateway resource.
        suboptions:
            redirect_type:
                description:
                    - Redirection type.
                choices:
                    - 'permanent'
                    - 'found'
                    - 'see_other'
                    - 'temporary'
            target_listener:
                description:
                    - Reference to a listener to redirect the request to.
            include_path:
                description:
                    - Include path in the redirected url.
            include_query_string:
                description:
                    - Include query string in the redirected url.
            name:
                description:
                    - Name of the resource that is unique within a resource group.
    frontend_ports:
        description:
            - List of frontend ports of the application gateway resource.
        suboptions:
            port:
                description:
                    - Frontend port.
            name:
                description:
                    - Name of the resource that is unique within a resource group. This name can be used to access the resource.
    backend_address_pools:
        description:
            - List of backend address pool of the application gateway resource.
        suboptions:
            backend_addresses:
                description:
                    - List of backend addresses.
                suboptions:
                    fqdn:
                        description:
                            - Fully qualified domain name (FQDN).
                    ip_address:
                        description:
                            - IP address.
            name:
                description:
                    - Resource that is unique within a resource group. This name can be used to access the resource.
    probes:
        description:
            - Probes available to the application gateway resource.
        suboptions:
            name:
                description:
                    - Name of the I(probe) that is unique within an Application Gateway.
            protocol:
                description:
                    - The protocol used for the I(probe).
                choices:
                    - 'http'
                    - 'https'
            host:
                description:
                    - Host name to send the I(probe) to.
            path:
                description:
                    - Relative path of I(probe).
                    - Valid path starts from '/'.
                    - Probe is sent to <Protocol>://<host>:<port><path>.
            timeout:
                description:
                    - The probe timeout in seconds.
                    - Probe marked as failed if valid response is not received with this timeout period.
                    - Acceptable values are from 1 second to 86400 seconds.
            interval:
                description:
                    - The probing interval in seconds.
                    - This is the time interval between two consecutive probes.
                    - Acceptable values are from 1 second to 86400 seconds.
            unhealthy_threshold:
                description:
                    - The I(probe) retry count.
                    - Backend server is marked down after consecutive probe failure count reaches UnhealthyThreshold.
                    - Acceptable values are from 1 second to 20.
            pick_host_name_from_backend_http_settings:
                description:
                    - Whether host header should be picked from the host name of the backend HTTP settings. Default value is false.
                type: bool
                default: False
    backend_http_settings_collection:
        description:
            - Backend http settings of the application gateway resource.
        suboptions:
            probe:
                description:
                    - Probe resource of an application gateway.
            port:
                description:
                    - The destination port on the backend.
            protocol:
                description:
                    - The protocol used to communicate with the backend.
                choices:
                    - 'http'
                    - 'https'
            cookie_based_affinity:
                description:
                    - Cookie based affinity.
                choices:
                    - 'enabled'
                    - 'disabled'
            connection_draining:
                version_added: "1.14.0"
                description:
                    - Connection draining of the backend http settings resource.
                type: dict
                suboptions:
                    drain_timeout_in_sec:
                        description:
                            - The number of seconds connection draining is active. Acceptable values are from 1 second to 3600 seconds.
                        type: int
                    enabled:
                        description:
                            - Whether connection draining is enabled or not.
                        type: bool
            request_timeout:
                description:
                    - Request timeout in seconds.
                    - Application Gateway will fail the request if response is not received within RequestTimeout.
                    - Acceptable values are from 1 second to 86400 seconds.
            authentication_certificates:
                description:
                    - List of references to application gateway authentication certificates.
                    - Applicable only when C(cookie_based_affinity) is enabled, otherwise quietly ignored.
                suboptions:
                    id:
                        description:
                            - Resource ID.
            host_name:
                description:
                    - Host header to be sent to the backend servers.
            pick_host_name_from_backend_address:
                description:
                    - Whether host header should be picked from the host name of the backend server. Default value is false.
            affinity_cookie_name:
                description:
                    - Cookie name to use for the affinity cookie.
            path:
                description:
                    - Path which should be used as a prefix for all C(http) requests.
                    - Null means no path will be prefixed. Default value is null.
            name:
                description:
                    - Name of the resource that is unique within a resource group. This name can be used to access the resource.
    http_listeners:
        description:
            - List of HTTP listeners of the application gateway resource.
        suboptions:
            frontend_ip_configuration:
                description:
                    - Frontend IP configuration resource of an application gateway.
            frontend_port:
                description:
                    - Frontend port resource of an application gateway.
            protocol:
                description:
                    - Protocol of the C(http) listener.
                choices:
                    - 'http'
                    - 'https'
            host_name:
                description:
                    - Host name of C(http) listener.
            ssl_certificate:
                description:
                    - SSL certificate resource of an application gateway.
            require_server_name_indication:
                description:
                    - Applicable only if I(protocol) is C(https). Enables SNI for multi-hosting.
            name:
                description:
                    - Name of the resource that is unique within a resource group. This name can be used to access the resource.
    request_routing_rules:
        description:
            - List of request routing rules of the application gateway resource.
        suboptions:
            rule_type:
                description:
                    - Rule type.
                choices:
                    - 'basic'
                    - 'path_based_routing'
            backend_address_pool:
                description:
                    - Backend address pool resource of the application gateway. Not used if I(rule_type) is C(path_based_routing).
            backend_http_settings:
                description:
                    - Backend C(http) settings resource of the application gateway.
            http_listener:
                description:
                    - Http listener resource of the application gateway.
            name:
                description:
                    - Name of the resource that is unique within a resource group. This name can be used to access the resource.
            redirect_configuration:
                description:
                    - Redirect configuration resource of the application gateway.
            url_path_map:
                description:
                    - URL path map resource of the application gateway. Required if I(rule_type) is C(path_based_routing).
    state:
        description:
            - Assert the state of the Public IP. Use C(present) to create or update a and
              C(absent) to delete.
        default: present
        choices:
            - absent
            - present

extends_documentation_fragment:
    - azure.azcollection.azure
    - azure.azcollection.azure_tags

author:
    - Zim Kalinowski (@zikalino)

'''

EXAMPLES = '''
- name: Create instance of Application Gateway
  azure_rm_appgateway_host:
    resource_group: myResourceGroup
    name: myAppGateway
    sku:
      name: standard_small
      tier: standard
      capacity: 2
    gateway_ip_configurations:
      - subnet:
          id: "{{ subnet_id }}"
        name: app_gateway_ip_config
    frontend_ip_configurations:
      - subnet:
          id: "{{ subnet_id }}"
        name: sample_gateway_frontend_ip_config
    frontend_ports:
      - port: 90
        name: ag_frontend_port
    backend_address_pools:
      - backend_addresses:
          - ip_address: 10.0.0.4
        name: test_backend_address_pool
    backend_http_settings_collection:
      - port: 80
        protocol: http
        cookie_based_affinity: enabled
        connection_draining:
            drain_timeout_in_sec: 60
            enabled: true
        name: sample_appgateway_http_settings
    http_listeners:
      - frontend_ip_configuration: sample_gateway_frontend_ip_config
        frontend_port: ag_frontend_port
        name: sample_http_listener
    request_routing_rules:
      - rule_type: Basic
        backend_address_pool: test_backend_address_pool
        backend_http_settings: sample_appgateway_http_settings
        http_listener: sample_http_listener
        name: rule1

- name: Create instance of Application Gateway by looking up virtual network and subnet
  azure_rm_appgateway_host:
    resource_group: myResourceGroup
    name: myAppGateway
    sku:
      name: standard_small
      tier: standard
      capacity: 2
    gateway_ip_configurations:
      - subnet:
          name: default
          virtual_network_name: my-vnet
        name: app_gateway_ip_config
    frontend_ip_configurations:
      - subnet:
          name: default
          virtual_network_name: my-vnet
        name: sample_gateway_frontend_ip_config
    frontend_ports:
      - port: 90
        name: ag_frontend_port
    backend_address_pools:
      - backend_addresses:
          - ip_address: 10.0.0.4
        name: test_backend_address_pool
    backend_http_settings_collection:
      - port: 80
        protocol: http
        cookie_based_affinity: enabled
        name: sample_appgateway_http_settings
    http_listeners:
      - frontend_ip_configuration: sample_gateway_frontend_ip_config
        frontend_port: ag_frontend_port
        name: sample_http_listener
    request_routing_rules:
      - rule_type: Basic
        backend_address_pool: test_backend_address_pool
        backend_http_settings: sample_appgateway_http_settings
        http_listener: sample_http_listener
        name: rule1

- name: Create instance of Application Gateway with path based rules
  azure_rm_appgateway_host:
    resource_group: myResourceGroup
    name: myAppGateway
    sku:
      name: standard_small
      tier: standard
      capacity: 2
    gateway_ip_configurations:
      - subnet:
          id: "{{ subnet_id }}"
        name: app_gateway_ip_config
    frontend_ip_configurations:
      - subnet:
          id: "{{ subnet_id }}"
        name: sample_gateway_frontend_ip_config
    frontend_ports:
      - port: 90
        name: ag_frontend_port
    backend_address_pools:
      - backend_addresses:
          - ip_address: 10.0.0.4
        name: test_backend_address_pool
    backend_http_settings_collection:
      - port: 80
        protocol: http
        cookie_based_affinity: enabled
        name: sample_appgateway_http_settings
    http_listeners:
      - frontend_ip_configuration: sample_gateway_frontend_ip_config
        frontend_port: ag_frontend_port
        name: sample_http_listener
    request_routing_rules:
      - rule_type: path_based_routing
        http_listener: sample_http_listener
        name: rule1
        url_path_map: path_mappings
    url_path_maps:
      - name: path_mappings
        default_backend_address_pool: test_backend_address_pool
        default_backend_http_settings: sample_appgateway_http_settings
        path_rules:
          - name: path_rules
            backend_address_pool: test_backend_address_pool
            backend_http_settings: sample_appgateway_http_settings
            paths:
              - "/abc"
              - "/123/*"
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
    from azure.core.polling import LROPoller
    from azure.mgmt.network import NetworkManagementClient
    from msrest.serialization import Model
except ImportError:
    # This is handled in azure_rm_common
    pass


class Actions:
    NoAction, Create, Update, Delete = range(4)

probe_match_spec = dict(
    statusCodes=dict(type='list', elements='str'),
    body=dict(type='str')
)


probe_spec = dict(
    host=dict(type='str'),
    port=dict(type='int'),
    interval=dict(type='int'),
    name=dict(type='str'),
    path=dict(type='str'),
    protocol=dict(type='str', choices=['http', 'https']),
    timeout=dict(type='int'),
    unhealthy_threshold=dict(type='int'),
    pick_host_name_from_backend_http_settings=dict(type='bool', default=False),
    match=dict(type='dict', options=probe_match_spec)
)


redirect_configuration_spec = dict(
    include_path=dict(type='bool'),
    include_query_string=dict(type='bool'),
    name=dict(type='str'),
    redirect_type=dict(type='str', choices=['permanent', 'found', 'see_other', 'temporary']),
    target_listener=dict(type='str')
)


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
            gateway_ip_configurations=dict(
                type='list'
            ),
            redirect_configurations=dict(
                type='list',
                elements='dict',
                options=redirect_configuration_spec
            ),
            frontend_ip_configurations=dict(
                type='list'
            ),
            backend_address_pools=dict(
                type='list'
            ),
            backend_http_settings_collection=dict(
                type='list'
            ),
            probes=dict(
                type='list',
                elements='dict',
                options=probe_spec
            ),
            http_listeners=dict(
                type='list'
            ),
            request_routing_rules=dict(
                type='list'
            ),
            state=dict(
                type='str',
                default='present',
                choices=['present', 'absent']
            ),
            force=dict(type='bool', default=False),
        )

        self.resource_group = None
        self.name = None
        self.parameters = dict()

        self.results = dict(changed=False)
        self.mgmt_client = None
        self.state = None
        self.to_do = Actions.NoAction

        super(AzureRMApplicationGateways, self).__init__(derived_arg_spec=self.module_arg_spec,
                                                         supports_check_mode=True,
                                                         supports_tags=True)

    def exec_module(self, **kwargs):
        """Main module execution method"""
        for key in list(self.module_arg_spec.keys()) + ['tags']:
            if hasattr(self, key):
                setattr(self, key, kwargs[key])
            elif kwargs[key] is not None:
                if key == "id":
                    self.parameters["id"] = kwargs[key]
                elif key == "redirect_configurations":
                    ev = deepcopy(kwargs[key])
                    for i in range(len(ev)):
                        item = ev[i]
                        if 'redirect_type' in item and item['redirect_type']:
                            item['redirect_type'] = _snake_to_camel(item['redirect_type'], True)
                        if 'target_listener' in item and item['target_listener']:
                            id = http_listener_id(self.subscription_id,
                                                  kwargs['resource_group'],
                                                  kwargs['name'],
                                                  item['target_listener'])
                            item['target_listener'] = {'id': id}
                    self.parameters["redirect_configurations"] = ev
                elif key == "frontend_ip_configurations":
                    ev = deepcopy(kwargs[key])
                    for i in range(len(ev)):
                        item = ev[i]
                        if 'private_ip_allocation_method' in item:
                            item['private_ip_allocation_method'] = _snake_to_camel(item['private_ip_allocation_method'], True)
                        if 'public_ip_address' in item:
                            id = public_ip_id(self.subscription_id,
                                              kwargs['resource_group'],
                                              item['public_ip_address'])
                            item['public_ip_address'] = {'id': id}
                        if 'subnet' in item and 'name' in item['subnet'] and 'virtual_network_name' in item['subnet']:
                            id = subnet_id(self.subscription_id,
                                           kwargs['resource_group'],
                                           item['subnet']['virtual_network_name'],
                                           item['subnet']['name'])
                            item['subnet'] = {'id': id}
                    self.parameters["frontend_ip_configurations"] = ev
                elif key == "backend_address_pools":
                    self.parameters["backend_address_pools"] = kwargs[key]
                elif key == "probes":
                    ev = deepcopy(kwargs[key])
                    for i in range(len(ev)):
                        item = ev[i]
                        if 'protocol' in item and item['protocol']:
                            item['protocol'] = _snake_to_camel(item['protocol'], True)
                        if 'pick_host_name_from_backend_http_settings' in item and item['pick_host_name_from_backend_http_settings'] and 'host' in item:
                            del item['host']
                    self.parameters["probes"] = ev
                elif key == "backend_http_settings_collection":
                    ev = deepcopy(kwargs[key])
                    for i in range(len(ev)):
                        item = ev[i]
                        if 'port' in item and type(item['port']) != int:
                            item['port'] = int(item['port'])
                        if 'protocol' in item:
                            item['protocol'] = _snake_to_camel(item['protocol'], True)
                        if 'cookie_based_affinity' in item:
                            item['cookie_based_affinity'] = _snake_to_camel(item['cookie_based_affinity'], True)
                        if 'probe' in item:
                            id = probe_id(self.subscription_id,
                                          kwargs['resource_group'],
                                          kwargs['name'],
                                          item['probe'])
                            item['probe'] = {'id': id}
                    self.parameters["backend_http_settings_collection"] = ev
                elif key == "http_listeners":
                    ev = deepcopy(kwargs[key])
                    for i in range(len(ev)):
                        item = ev[i]
                        if 'frontend_ip_configuration' in item:
                            #id = frontend_ip_configuration_id(self.subscription_id,
                            #                                  kwargs['resource_group'],
                            #                                  kwargs['name'],
                            #                                  item['frontend_ip_configuration'])
                            #item['frontend_ip_configuration'] = {'id': id}
                            None
                        if 'frontend_port' in item and type(item['frontend_port']) != int:
                            item['frontend_port'] = int(item['frontend_port'])
                        if 'ssl_certificate' in item:
                            id = ssl_certificate_id(self.subscription_id,
                                                    kwargs['resource_group'],
                                                    kwargs['name'],
                                                    item['ssl_certificate'])
                            item['ssl_certificate'] = {'id': id}
                        if 'protocol' in item:
                            item['protocol'] = _snake_to_camel(item['protocol'], True)
                        ev[i] = item
                    self.parameters["http_listeners"] = ev
                elif key == "request_routing_rules":
                    ev = deepcopy(kwargs[key])
                    for i in range(len(ev)):
                        item = ev[i]
                        if 'rule_type' in item and item['rule_type'] == 'path_based_routing' and 'backend_address_pool' in item:
                            del item['backend_address_pool']
                        if 'backend_address_pool' in item:
                            id = backend_address_pool_id(self.subscription_id,
                                                         kwargs['resource_group'],
                                                         kwargs['name'],
                                                         item['backend_address_pool'])
                            item['backend_address_pool'] = {'id': id}
                        if 'backend_http_settings' in item:
                            id = backend_http_settings_id(self.subscription_id,
                                                          kwargs['resource_group'],
                                                          kwargs['name'],
                                                          item['backend_http_settings'])
                            item['backend_http_settings'] = {'id': id}
                        if 'http_listener' in item:
                            id = http_listener_id(self.subscription_id,
                                                  kwargs['resource_group'],
                                                  kwargs['name'],
                                                  item['http_listener'])
                            item['http_listener'] = {'id': id}
                        if 'protocol' in item:
                            item['protocol'] = _snake_to_camel(item['protocol'], True)
                        if 'rule_type' in item:
                            item['rule_type'] = _snake_to_camel(item['rule_type'], True)
                        if 'redirect_configuration' in item:
                            id = redirect_configuration_id(self.subscription_id,
                                                           kwargs['resource_group'],
                                                           kwargs['name'],
                                                           item['redirect_configuration'])
                            item['redirect_configuration'] = {'id': id}
                        if 'url_path_map' in item:
                            id = url_path_map_id(self.subscription_id,
                                                 kwargs['resource_group'],
                                                 kwargs['name'],
                                                 item['url_path_map'])
                            item['url_path_map'] = {'id': id}
                        if 'rewrite_rule_set' in item:
                            id = rewrite_rule_set_id(self.subscription_id,
                                                    kwargs['resource_group'],
                                                    kwargs['name'],
                                                    item['rewrite_rule_set'])
                            item['rewrite_rule_set'] = {'id': id}                        
                        ev[i] = item
                    self.parameters["request_routing_rules"] = ev
                elif key == "etag":
                    self.parameters["etag"] = kwargs[key]

        old_response = None
        response = None

        self.mgmt_client = self.get_mgmt_svc_client(NetworkManagementClient,
                                                    base_url=self._cloud_environment.endpoints.resource_manager,
                                                    is_track2=True)

        self.cgmodels = self.mgmt_client.application_gateways.models 

        resource_group = self.get_resource_group(self.resource_group)

        if "location" not in self.parameters:
            self.parameters["location"] = resource_group.location

        old_response = self.get_applicationgateway()

        if not old_response:
            self.log("Application Gateway instance doesn't exist")
            if self.state == 'absent':
                self.log("Old instance didn't exist")
            else:
                self.fail("Application Gateway instance '{0}@{1}' doesn't exist".format(self.name, self.resource_group))
        else:
            self.log("Application Gateway instance already exists")
            if self.state == 'absent':
                self.to_do = Actions.Delete
            elif self.state == 'present':
                self.log("Need to check if Application Gateway instance has to be deleted or may be updated")
                self.to_do = Actions.Update


        if (self.to_do == Actions.Update) or (self.to_do == Actions.Delete):
            if (self.to_do == Actions.Update):
                self.object_assign_original_port(self.parameters, old_response)
                self.object_assign_rule_priority(self.parameters, old_response)

            self.dict_assign_appgateway(self.parameters, old_response)
            #section host
            object_assign_original(old_response, self.parameters, 'backend_address_pools', self.to_do)
            object_assign_original(old_response, self.parameters, 'probes', self.to_do)
            object_assign_original(old_response, self.parameters, 'backend_http_settings_collection', self.to_do)
            object_assign_original(old_response, self.parameters, 'http_listeners', self.to_do)
            object_assign_original(old_response, self.parameters, 'request_routing_rules', self.to_do)
            object_assign_original(old_response, self.parameters, 'redirect_configurations', self.to_do)
            
            if (not compare_arrays(old_response, self.parameters, 'backend_address_pools', self.to_do) or
            not compare_arrays(old_response, self.parameters, 'probes', self.to_do) or
            not compare_arrays(old_response, self.parameters, 'backend_http_settings_collection', self.to_do) or
            not compare_arrays(old_response, self.parameters, 'request_routing_rules', self.to_do) or
            not compare_arrays(old_response, self.parameters, 'redirect_configurations', self.to_do) or
            not compare_arrays(old_response, self.parameters, 'http_listeners', self.to_do)):
                pass
            else:
                self.to_do = Actions.NoAction

        if (self.to_do == Actions.Create) or (self.to_do == Actions.Update) or (self.to_do == Actions.Delete):
            self.log("Need to Create / Update the Application Gateway instance")

            if self.check_mode:
                self.results['changed'] = True
                self.results["parameters"] = self.parameters
                return self.results

            response = self.create_update_applicationgateway()

            if not old_response:
                self.results['changed'] = True
            else:
                self.results['changed'] = old_response.__ne__(response)
            self.log("Creation / Update done")
        else:
            self.log("Application Gateway instance unchanged")
            self.results['changed'] = False
            response = old_response

        if response:
            self.results["id"] = response["id"]

        return self.results

    def create_update_applicationgateway(self):
        '''
        Creates or updates Application Gateway with the specified configuration.

        :return: deserialized Application Gateway instance state dictionary
        '''
        self.log("Creating / Updating the Application Gateway instance {0}".format(self.name))

        try:
            response = self.mgmt_client.application_gateways.begin_create_or_update(resource_group_name=self.resource_group,
                                                                              application_gateway_name=self.name,
                                                                              parameters=self.parameters)
            if isinstance(response, LROPoller):
                response = self.get_poller_result(response)

        except CloudError as exc:
            self.log('Error attempting to create the Application Gateway instance.')
            self.fail("Error creating the Application Gateway instance: {0}".format(str(exc)))
        return response.as_dict()

    def delete_applicationgateway(self):
        '''
        Deletes specified Application Gateway instance in the specified subscription and resource group.

        :return: True
        '''
        self.log("Deleting the Application Gateway instance {0}".format(self.name))
        try:
            response = self.mgmt_client.application_gateways.begin_delete(resource_group_name=self.resource_group,
                                                                    application_gateway_name=self.name)
        except CloudError as e:
            self.log('Error attempting to delete the Application Gateway instance.')
            self.fail("Error deleting the Application Gateway instance: {0}".format(str(e)))

        return True

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

    def dict_assign_appgateway(self, patch, origin):
        attribute_map = set(self.cgmodels.ApplicationGateway._attribute_map.keys()) - set(self.cgmodels.ApplicationGateway._validation.keys())
        for key in attribute_map:
            if not key in patch and key in origin:
                patch[key] = origin[key]

    def get_private_frontend_ports(self, old_params, private_ip_configuration_id):
        private_ports = {}
        old = old_params.get('frontend_ports') or []
        oldListeners = old_params.get('http_listeners') or []
        for port in old:
            private_ports[port['port']] = False
            for listener in oldListeners:
                if port['id'] == listener['frontend_port']['id']:
                    frontend_ip_configuration = listener['frontend_ip_configuration'] 
                    private_ports[port['port']] = frontend_ip_configuration['id'] == private_ip_configuration_id
                    break
        return private_ports

    def object_assign_original_port(self, new_params, old_params):
        old = old_params.get('frontend_ports') or []
        newListeners = new_params.get('http_listeners') or []
        
        frontend_ip_configuration = None
        private_ip_configuration = None
        private_ip_configuration_id = ''
        for item in old_params.get('frontend_ip_configurations'):
            if 'public_ip_address' in item:
                frontend_ip_configuration = item
            else:
                private_ip_configuration = item
                private_ip_configuration_id = item['id']
        private_ports = self.get_private_frontend_ports(old_params, private_ip_configuration_id)
        oldports = {}
        for item in old:
            oldports[item['port']] = item['id']

        for item in newListeners:
            port = item['frontend_port']
            if not port in private_ports:
                self.fail("Error creating host, port {0} must be configured for gateway : {1}".format(port, self.name))

            if private_ports[port]:
                item['frontend_ip_configuration'] = {'id': private_ip_configuration['id']}
            else:
                item['frontend_ip_configuration'] = {'id': frontend_ip_configuration['id']}
            item['frontend_port'] = {'id': oldports[port]}
        
    def object_assign_rule_priority(self, new_params, old_params):
        old_rules = old_params.get('request_routing_rules') or []
        new_rules = new_params.get('request_routing_rules') or []
        indexed_rules = {}
        rule_priority = -1

        for item in new_rules:
            indexed_rules[item['name']] = item
        #Priority must be unique across all the request routing rules
        for item in old_rules:
            if 'priority' in item:
                rule_priority = max(int(item['priority']), rule_priority)
                if item['name'] in indexed_rules:
                    new_item = indexed_rules[item['name']]
                    if not 'priority' in new_item:
                        new_item['priority'] = rule_priority

        if rule_priority > 0:
            rule_priority += 10
            for item in new_rules:
                if not 'priority' in item:
                    item['priority'] = rule_priority
                    rule_priority += 1


def public_ip_id(subscription_id, resource_group_name, name):
    """Generate the id for a frontend ip configuration"""
    return '/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Network/publicIPAddresses/{2}'.format(
        subscription_id,
        resource_group_name,
        name
    )


def frontend_ip_configuration_id(subscription_id, resource_group_name, appgateway_name, name):
    """Generate the id for a frontend ip configuration"""
    return '/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Network/applicationGateways/{2}/frontendIPConfigurations/{3}'.format(
        subscription_id,
        resource_group_name,
        appgateway_name,
        name
    )


def frontend_port_id(subscription_id, resource_group_name, appgateway_name, name):
    """Generate the id for a frontend port"""
    return '/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Network/applicationGateways/{2}/frontendPorts/{3}'.format(
        subscription_id,
        resource_group_name,
        appgateway_name,
        name
    )


def redirect_configuration_id(subscription_id, resource_group_name, appgateway_name, name):
    """Generate the id for a redirect configuration"""
    return '/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Network/applicationGateways/{2}/redirectConfigurations/{3}'.format(
        subscription_id,
        resource_group_name,
        appgateway_name,
        name
    )


def ssl_certificate_id(subscription_id, resource_group_name, ssl_certificate_name, name):
    """Generate the id for a frontend port"""
    return '/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Network/applicationGateways/{2}/sslCertificates/{3}'.format(
        subscription_id,
        resource_group_name,
        ssl_certificate_name,
        name
    )


def backend_address_pool_id(subscription_id, resource_group_name, appgateway_name, name):
    """Generate the id for an address pool"""
    return '/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Network/applicationGateways/{2}/backendAddressPools/{3}'.format(
        subscription_id,
        resource_group_name,
        appgateway_name,
        name
    )


def probe_id(subscription_id, resource_group_name, appgateway_name, name):
    """Generate the id for a probe"""
    return '/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Network/applicationGateways/{2}/probes/{3}'.format(
        subscription_id,
        resource_group_name,
        appgateway_name,
        name
    )


def backend_http_settings_id(subscription_id, resource_group_name, appgateway_name, name):
    """Generate the id for a http settings"""
    return '/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Network/applicationGateways/{2}/backendHttpSettingsCollection/{3}'.format(
        subscription_id,
        resource_group_name,
        appgateway_name,
        name
    )


def http_listener_id(subscription_id, resource_group_name, appgateway_name, name):
    """Generate the id for a http listener"""
    return '/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Network/applicationGateways/{2}/httpListeners/{3}'.format(
        subscription_id,
        resource_group_name,
        appgateway_name,
        name
    )


def url_path_map_id(subscription_id, resource_group_name, appgateway_name, name):
    """Generate the id for a url path map"""
    return '/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Network/applicationGateways/{2}/urlPathMaps/{3}'.format(
        subscription_id,
        resource_group_name,
        appgateway_name,
        name
    )


def subnet_id(subscription_id, resource_group_name, virtual_network_name, name):
    """Generate the id for a subnet in a virtual network"""
    return '/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Network/virtualNetworks/{2}/subnets/{3}'.format(
        subscription_id,
        resource_group_name,
        virtual_network_name,
        name
    )

def rewrite_rule_set_id(subscription_id, resource_group_name, appgateway_name, name):
    """Generate the id for a rewrite rule set in an application gateway"""
    return '/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Network/applicationGateways/{2}/rewriteRuleSets/{3}'.format(
        subscription_id,
        resource_group_name,
        appgateway_name,
        name
    )


def compare_arrays(old_params, new_params, param_name, to_do = Actions.Update):
    old = old_params.get(param_name) or []
    new = new_params.get(param_name) or []

    oldd = array_to_dict(old)
    newd = array_to_dict(new)

    if to_do != Actions.Delete:
        newd = dict_merge(oldd, newd)
    return newd == oldd


def array_to_dict(array):
    '''Converts list object to dictionary object, including any nested properties on elements.'''
    new = {}
    for index, item in enumerate(array):
        new[index] = deepcopy(item)
        if isinstance(item, dict):
            for nested in item:
                if isinstance(item[nested], list):
                    new[index][nested] = array_to_dict(item[nested])
    return new




def object_assign_original(old_params, new_params, param_name, to_do = Actions.Update, index_name = 'name'):
    old = old_params.get(param_name) or []
    new = new_params.get(param_name) or []
    newArray = []
    newvalues = {}
    for item in new:
        newvalues[item[index_name]] = item
    for item in old:
        if not item[index_name] in newvalues:
            newArray.append(item)
        elif to_do != Actions.Delete:
            newArray.append(newvalues.pop(item[index_name]))
    if to_do != Actions.Delete:
        for key in newvalues:
            newArray.append(newvalues[key])
    new_params[param_name] = newArray

def main():
    """Main execution"""
    AzureRMApplicationGateways()


if __name__ == '__main__':
    main()
