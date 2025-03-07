#!/usr/bin/python
#
# Copyright (c) 2019 Zim Kalinowski, (@zikalino)
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: azure_rm_sqlmanaged_info
version_added: "0.1.2"
short_description: Get Azure SQL Database facts
description:
    - Get facts of Azure SQL Database.

options:
    resource_group:
        description:
            - The name of the resource group that contains the resource. You can obtain this value from the Azure Resource Manager API or the portal.
        required: True
    instance_name:
        description:
            - The name of the server.
        required: True
    name:
        description:
            - The name of the database.
    tags:
        description:
            - Limit results by providing a list of tags. Format tags as 'key' or 'key:value'.

extends_documentation_fragment:
    - azure.azcollection.azure

author:
    - Zim Kalinowski (@zikalino)

'''

EXAMPLES = '''
  - name: Get instance of SQL Database
    azure_rm_sqlmanaged_info:
      resource_group: testrg
      instance_name: testserver
      name: testdb

  - name: List instances of SQL Database
    azure_rm_sqlmanaged_info:
      resource_group: testrg
      instance_name: testserver

  - name: List instances of SQL Database
    azure_rm_sqlmanaged_info:
      resource_group: testrg
      instance_name: testserver
'''

RETURN = '''
databases:
    description:
        - A list of dictionaries containing facts for SQL Database.
    returned: always
    type: complex
    contains:
        id:
            description:
                - Resource ID.
            returned: always
            type: str
            sample: /subscriptions/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/resourceGroups/testrg/providers/Microsoft.Sql/servers/testserver/databases/testdb
        name:
            description:
                - Database name.
            returned: always
            type: str
            sample: testdb
        location:
            description:
                - Resource location.
            returned: always
            type: str
            sample: southeastasia
        tags:
            description:
                - Resource tags.
            returned: always
            type: dict
            sample: { 'taga':'aaa', 'tagb':'bbb' }
        sku:
            description:
                - The name and tier of the SKU.
            returned: always
            type: complex
            contains:
                name:
                    description:
                        - The name of the SKU.
                    returned: always
                    type: str
                    sample: BC_Gen4_2
                tier:
                    description:
                        - The SKU tier.
                    returned: always
                    type: str
                    sample: BusinessCritical
                capacity:
                    description:
                        - The SKU capacity.
                    returned: always
                    type: int
                    sample: 2
        kind:
            description:
                - Kind of database. This is metadata used for the Azure portal experience.
            returned: always
            type: str
            sample: v12.0,user
        collation:
            description:
                - The collation of the database.
            returned: always
            type: str
            sample: SQL_Latin1_General_CP1_CI_AS
        status:
            description:
                - The status of the database.
            returned: always
            type: str
            sample: Online
        zone_redundant:
            description:
                - Whether or not this database is zone redundant, which means the replicas of this database will be spread across multiple availability zones.
            returned: always
            type: bool
            sample: true
'''

from ansible_collections.azure.azcollection.plugins.module_utils.azure_rm_common import AzureRMModuleBase

try:
    from msrestazure.azure_exceptions import CloudError
    from azure.mgmt.sql import SqlManagementClient
    from msrest.serialization import Model
except ImportError:
    # This is handled in azure_rm_common
    pass


class AzureRMSqlManagedInfo(AzureRMModuleBase):
    def __init__(self):
        # define user inputs into argument
        self.module_arg_spec = dict(
            resource_group=dict(
                type='str',
                required=True
            ),
            instance_name=dict(
                type='str',
                required=True
            ),
            name=dict(
                type='str'
            ),
            tags=dict(
                type='list'
            )
        )
        # store the results of the module operation
        self.results = dict(
            changed=False
        )
        self.resource_group = None
        self.instance_name = None
        self.name = None
        self.tags = None
        super(AzureRMSqlManagedInfo, self).__init__(self.module_arg_spec, supports_check_mode=True, supports_tags=False)

    def exec_module(self, **kwargs):
        for key in self.module_arg_spec:
            setattr(self, key, kwargs[key])

        if self.name is not None:
            self.results['databases'] = self.get()
        else:
            self.results['databases'] = self.list_by_instance()
        return self.results

    def get(self):
        response = None
        results = []
        try:
            #resource_group_name, managed_instance_name, database_name,
            response = self.sql_client.managed_databases.get(resource_group_name=self.resource_group,
                                                     managed_instance_name=self.instance_name,
                                                     database_name=self.name)
            self.log("Response : {0}".format(response))
        except CloudError as e:
            self.log('Could not get facts for Databases.')

        if response and self.has_tags(response.tags, self.tags):
            results.append(self.format_item(response))

        return results

    def list_by_instance(self):
        response = None
        results = []
        try:
            response = self.sql_client.managed_databases.list_by_instance(resource_group_name=self.resource_group,
                                                                managed_instance_name=self.instance_name)
            self.log("Response : {0}".format(response))
        except CloudError as e:
            self.fail('Could not get facts for Databases.')

        if response is not None:
            for item in response:
                if self.has_tags(item.tags, self.tags):
                    results.append(self.format_item(item))

        return results

    def format_item(self, item):
        d = item.as_dict()
        d = {
            'resource_group': self.resource_group,
            'id': d.get('id', None),
            'name': d.get('name', None),
            'location': d.get('location', None),
            'tags': d.get('tags', None),
            'sku': {
                'name': d.get('current_service_objective_name', None),
                'tier': d.get('sku', {}).get('tier', None),
                'capacity': d.get('sku', {}).get('capacity', None)
            },
            'kind': d.get('kind', None),
            'collation': d.get('collation', None),
            'status': d.get('status', None),
            'zone_redundant': d.get('zone_redundant', None)
        }
        return d


def main():
    AzureRMSqlManagedInfo()


if __name__ == '__main__':
    main()
