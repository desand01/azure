#!/usr/bin/python
#
# Copyright (c) 2020 XiuxiSun, (@Fred-sun)
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
from email.policy import default
from xml.dom.minidom import Element
from ansible.module_utils.common.dict_transformations import _camel_to_snake, _snake_to_camel
__metaclass__ = type


DOCUMENTATION = '''
---
module: azure_rm_azurefirewallrulegroup
version_added: '1.10.0'
short_description: Manage Azure RuleCollectionGroup instance
description:
    - Create, update and delete instance of Azure RuleCollectionGroup.
options:
    resource_group:
        description:
            - The resource group name of the RuleCollectionGroup.
        required: true
        type: str
    name:
        description:
            - The name of the RuleCollectionGroup.
        required: true
        type: str
    state:
        description:
            - Assert the state of the RuleCollectionGroup.
            - Use C(present) to create or update an RuleCollectionGroup and C(absent) to delete it.
        default: present
        type: str
        choices:
            - absent
            - present
extends_documentation_fragment:
    - azure.azcollection.azure
    - azure.azcollection.azure_tags
author:
    - 

'''

EXAMPLES = '''
    - name: Create a RuleCollectionGroup
      azure_rm_azurefirewallrulegroup:
        resource_group: myResourceGroup
        name: my_firewall_policy_name
        address_prefix: 10.2.0.0/24
        sku: Standard
        enable_virtual_router_route_propogation: false
        virtual_wan:
          id: /subscriptions/xxx-xxx/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualWans/fredwan

    - name: Delete RuleCollectionGroup
      azure_rm_azurefirewallrulegroup:
        resource_group: myResourceGroup
        name: my_firewall_policy_name
        state: absent
'''

RETURN = '''
state:


'''

from ansible_collections.azure.azcollection.plugins.module_utils.azure_rm_common_ext import AzureRMModuleBaseExt
try:
    from msrestazure.azure_exceptions import CloudError
    from msrestazure.azure_operation import AzureOperationPoller
    from msrest.polling import LROPoller
except ImportError:
    # This is handled in azure_rm_common
    pass

action_spec = dict(
    type=dict(
        type="str",
        choices=["Allow","Deny","DNAT"]
    )
)
group_ip_spec = dict(
    resource_group=dict(
        type="str"
    ),
    name=dict(
        type="str",
        required=True
    )
)
rule_spec = dict(
    name=dict(type='str', required=True),
    rule_type=dict(
        type='str', 
        choices=['ApplicationRule','NatRule','NetworkRule'],
        required=True),
    ip_protocols=dict(type='list', elements='str',choices=['TCP','UDP','Any','ICMP'], purgeIfNone=True),
    source_addresses=dict(type='list', elements='str', purgeIfNone=True),
    destination_addresses=dict(type='list', elements='str', purgeIfNone=True),
    destination_ports=dict(type='list', elements='str', purgeIfNone=True),
    source_ip_groups=dict(type='list', elements='dict', options=group_ip_spec, purgeIfNone=True),
    destination_ip_groups=dict(type='list', elements='dict', options=group_ip_spec, purgeIfNone=True),
    destination_fqdns=dict(type='list', elements='str', purgeIfNone=True),
)
rule_collection_spec = dict(
    name=dict(type='str', required=True),
    rule_collection_type=dict(
        type='str', 
        choices=["FirewallPolicyFilterRuleCollection","FirewallPolicyNatRuleCollection"]
        ),
    priority=dict(type='int'),
    action=dict(type='dict', options=action_spec),
    rules=dict(type='list', elements='dict', options=rule_spec)
)

class Actions:
    NoAction, Create, Update, Delete = range(4)


class AzureRMAzureFirewallpolicy(AzureRMModuleBaseExt):
    def __init__(self):
        self.module_arg_spec = dict(
            resource_group=dict(
                type='str',
                required=True
            ),
            firewall_policy_name=dict(
                type='str',
                required=True
            ),
            name=dict(
                type='str',
                required=True
            ),
            priority=dict(
                type='int'
            ),
            rule_collections=dict(
                type='list', 
                elements='dict',
                purgeIfNone=True,
                options=rule_collection_spec
            ),
            force=dict(type='bool', default=False),
            state=dict(
                type='str',
                default='present',
                choices=['present', 'absent']
            )
        )

        self.resource_group = None
        self.firewall_policy_name = None
        self.name = None
        #self.priority = None
        self.force = None
        self.body = {}

        self.results = dict(changed=False)
        self.state = None
        self.to_do = Actions.NoAction

        super(AzureRMAzureFirewallpolicy, self).__init__(derived_arg_spec=self.module_arg_spec,
                                                supports_check_mode=True,
                                                supports_tags=True)

    def exec_module(self, **kwargs):
        for key in list(self.module_arg_spec.keys()):
            if hasattr(self, key):
                setattr(self, key, kwargs[key])
            elif kwargs[key] is not None:
                self.body[key] = kwargs[key]

        self.inflate_parameters(self.module_arg_spec, self.body, 0)
        self.replace_dict_to_ip_group()

        #resource_group = self.get_resource_group(self.resource_group)

        old_response = None
        response = None

        old_response = self.get_resource()

        if not old_response:
            if self.state == 'present':
                self.to_do = Actions.Create
        else:
            if self.state == 'absent' \
            and (not 'rule_collections' in self.body or len(self.body['rule_collections']) == 0):
                #only detele group if no collection is givent
                self.to_do = Actions.Delete
            else:
                if self.state == 'absent':
                    object_assign_original(old_response, self.body, 'rule_collections', Actions.Delete)
                elif not self.force:
                    object_assign_original(old_response, self.body, 'rule_collections', self.to_do)
                self.dict_assign_origin(self.network_models.FirewallPolicyRuleCollectionGroup, self.body, old_response)
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

    def replace_dict_to_ip_group(self):
        for rule_collection in self.body['rule_collections'] or []:
            for rule in rule_collection['rules'] or []:
                self.dict_to_ip_group(rule)

    def dict_to_ip_group(self, rule):
        rule['source_ip_groups'] = [
            self.ip_group_id(item)
        for item in rule['source_ip_groups']] if rule['source_ip_groups'] else []

        rule['destination_ip_groups'] = [
            self.ip_group_id(item)
        for item in rule['destination_ip_groups']] if rule['destination_ip_groups'] else []

    def ip_group_id(self, item):
        return "/subscriptions/{0}/resourcegroups/{1}/providers/Microsoft.Network/ipGroups/{2}".format(
                self.subscription_id,
                item["resource_group"] or self.resource_group,
                item["name"]
                )

    def create_update_resource(self):
        try:
            self.inflate_parameters(self.module_arg_spec, self.body, 1)
            self.validate_priorities()
            response = self.network_client.firewall_policy_rule_collection_groups.create_or_update(resource_group_name=self.resource_group,
                                                                         firewall_policy_name=self.firewall_policy_name,
                                                                         rule_collection_group_name=self.name,
                                                                         parameters=self.body)
            if isinstance(response, AzureOperationPoller) or isinstance(response, LROPoller):
                response = self.get_poller_result(response)
        except CloudError as exc:
            self.log('Error attempting to create the RuleCollectionGroup instance.')
            self.fail('Error creating the RuleCollectionGroup instance: {0}'.format(str(exc)))
        return response.as_dict()

    def delete_resource(self):
        try:
            response = self.network_client.firewall_policy_rule_collection_groups.delete(resource_group_name=self.resource_group,
                                                                                    firewall_policy_name=self.firewall_policy_name,
                                                                                    rule_collection_group_name=self.name)
        except CloudError as e:
            self.log('Error attempting to delete the RuleCollectionGroup instance.')
            self.fail('Error deleting the RuleCollectionGroup instance: {0}'.format(str(e)))

        return True

    def get_resource(self):
        try: ##resource_group_name, firewall_policy_name, rule_collection_group_name,
            response = self.network_client.firewall_policy_rule_collection_groups.get(resource_group_name=self.resource_group,
                                                                firewall_policy_name=self.firewall_policy_name,
                                                                rule_collection_group_name=self.name)
            
        except CloudError as e:
            return False
        return response.as_dict()

    def format_item(self, item):
        if item is None:
            return None
        elif hasattr(item, 'as_dict'):
            return [item.as_dict()]
        else:
            result = []
            items = list(item)
            for tmp in items:
                result.append(tmp.as_dict())
            return result

    def dict_assign_origin(self, model, patch, origin):
        attribute_map = set(model._attribute_map.keys()) #- set(model._validation.keys())
        for key in attribute_map:
            if not key in patch and key in origin:
                patch[key] = origin[key]

    def validate_priorities(self):
        priorities = dict()
        for rule_collection in self.body['rule_collections'] or []:
            priority = str(rule_collection['priority'])
            if priority in priorities:
                self.fail('Error creating the RuleCollection instance: {0} - duplicate priority {1}'.format(rule_collection['name'], priority))
            priorities[priority] = True

    def inflate_parameters(self, spec, body, level):
        if isinstance(body, list):
            for item in body:
                self.inflate_parameters(spec, item, level)
            return
        if not isinstance(body, dict):
            return
        for name in spec.keys():
            # first check if option was passed
            param = body.get(name)
            if param is None:
                if spec[name].get('purgeIfNone', False):
                    body.pop(name, None)
                continue
            if isinstance(param, list) and len(param) == 0:
                if spec[name].get('purgeIfNone', False):
                    body.pop(name, None)
                continue
            # check if pattern needs to be used
            pattern = spec[name].get('pattern', None)
            if pattern:
                if pattern == 'camelize':
                    param = _snake_to_camel(param, True)
                elif isinstance(pattern, list):
                    normalized = None
                    for p in pattern:
                        normalized = self.normalize_resource_id(param, p)
                        body[name] = normalized
                        if normalized is not None:
                            break
                else:
                    param = self.normalize_resource_id(param, pattern)
                    body[name] = param
            disposition = spec[name].get('disposition', '*')
            if level == 0 and not disposition.startswith('/'):
                continue
            if disposition == '/':
                disposition = '/*'
            parts = disposition.split('/')
            if parts[0] == '':
                # should fail if level is > 0?
                parts.pop(0)
            target_dict = body
            elem = body.pop(name)
            while len(parts) > 1:
                target_dict = target_dict.setdefault(parts.pop(0), {})
            targetName = parts[0] if parts[0] != '*' else name
            target_dict[targetName] = elem
            if spec[name].get('options'):
                self.inflate_parameters(spec[name].get('options'), target_dict[targetName], level + 1)

def vnet_id(subscription_id, resource_group_name, virtual_network_name):
    """Generate the id for a virtual network"""
    return '/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Network/virtualNetworks/{2}'.format(
        subscription_id,
        resource_group_name,
        virtual_network_name
    )

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
            newItem = newvalues.pop(item[index_name])
            if 'rules' in item:
                object_assign_original(item, newItem, 'rules', to_do)
            newArray.append(newItem)
    if to_do != Actions.Delete:
        for key in newvalues:
            newArray.append(newvalues[key])
    new_params[param_name] = newArray

def main():
    AzureRMAzureFirewallpolicy()


if __name__ == '__main__':
    main()
