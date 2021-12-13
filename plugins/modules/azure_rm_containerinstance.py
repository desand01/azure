#!/usr/bin/python
#
# Copyright (c) 2017 Zim Kalinowski, <zikalino@microsoft.com>
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: azure_rm_containerinstance
version_added: "0.1.2"
short_description: Manage an Azure Container Instance
description:
    - Create, update and delete an Azure Container Instance.

options:
    resource_group:
        description:
            - Name of resource group.
        type: str
        required: true
    name:
        description:
            - The name of the container group.
        required: true
        type: str
    os_type:
        description:
            - The OS type of containers.
        type: str
        choices:
            - Linux
            - Windows
        default: Linux
    state:
        description:
            - Assert the state of the container instance. Use C(present) to create or update an container instance and C(absent) to delete it.
        type: str
        default: present
        choices:
            - absent
            - present
            - restart
            - execute
    restart_wait:
        description:
            - Wait for containers group to restart
            - If absent, do not wait
            - Task fail if waiting time expired et containers group is not running
        type: int
        default: None
    ip_address:
        description:
            - The IP address type of the container group.
            - Default is C(none) and creating an instance without public IP.
        type: str
        choices:
            - Public
            - Private
            - none
        default: 'none'
    dns_name_label:
        description:
            - The Dns name label for the IP.
        type: str
    ports:
        description:
            - List of ports exposed within the container group.
            - This option is deprecated, using I(ports) under I(containers)".
        type: list
        elements: int
    location:
        description:
            - Valid azure location. Defaults to location of the resource group.
        type: str
    registry_login_server:
        description:
            - The container image registry login server.
        type: str
    registry_username:
        description:
            - The username to log in container image registry server.
        type: str
    registry_password:
        description:
            - The password to log in container image registry server.
        type: str
    restart_wait:
        description:
            - When restarting container, wait in secondes for completion.
            - If missing, restart async
        type: int
    terminal:
        description:
            - Required when executing command in container.
        type: dict
        suboptions:
            container:
                description:
                    - The name of the container instance.
                type: str
                required: true
            command:
                description:
                    - Interpreter
                type: str
                default: '/bin/sh'
            lines:
                description:
                    - List of commandes to execute.
                type: list
                elements: str
                required: true
            wait_timeout:
                description:
                    - Wait time in secondes between message from container
                type: int
                default: 120
            wait_regex:
                description:
                    - Wait until regex match last received message from container or wait_timeout is reach
                type: str
                default: '[#$:] $'
    containers:
        description:
            - List of containers.
            - Required when creation.
        type: list
        elements: dict
        suboptions:
            name:
                description:
                    - The name of the container instance.
                type: str
                required: true
            image:
                description:
                    - The container image name.
                type: str
                required: true
            memory:
                description:
                    - The required memory of the containers in GB.
                type: float
                default: 1.5
            cpu:
                description:
                    - The required number of CPU cores of the containers.
                type: float
                default: 1
            ports:
                description:
                    - List of ports exposed within the container group.
                type: list
                elements: int
            environment_variables:
                description:
                    - List of container environment variables.
                    - When updating existing container all existing variables will be replaced by new ones.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Environment variable name.
                        type: str
                        required: true
                    value:
                        description:
                            - Environment variable value.
                        type: str
                        required: true
                    is_secure:
                        description:
                            - Is variable secure.
                        type: bool
            volume_mounts:
                description:
                    - The volume mounts for the container instance
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - The name of the volume mount
                        required: true
                        type: str
                    mount_path:
                        description:
                            - The path within the container where the volume should be mounted
                        required: true
                        type: str
                    read_only:
                        description:
                            - The flag indicating whether the volume mount is read-only
                        type: bool
            commands:
                description:
                    - List of commands to execute within the container instance in exec form.
                    - When updating existing container all existing commands will be replaced by new ones.
                type: list
                elements: str
    restart_policy:
        description:
            - Restart policy for all containers within the container group.
        type: str
        choices:
            - always
            - on_failure
            - never
    volumes:
        description:
            - List of Volumes that can be mounted by containers in this container group.
        type: list
        elements: dict
        suboptions:
            name:
                description:
                    - The name of the Volume
                required: true
                type: str
            azure_file:
                description:
                    - The Azure File volume
                type: dict
                suboptions:
                    share_name:
                        description:
                            - The name of the Azure File share to be mounted as a volume
                        required: true
                        type: str
                    read_only:
                        description:
                            - The flag indicating whether the Azure File shared mounted as a volume is read-only
                        type: bool
                    storage_account_name:
                        description:
                            - The name of the storage account that contains the Azure File share
                        required: true
                        type: str
                    storage_account_key:
                        description:
                            - The storage account access key used to access the Azure File share
                        required: true
                        type: str
            empty_dir:
                description:
                    - The empty directory volume
                type: dict
            secret:
                description:
                    - The secret volume
                type: dict
            git_repo:
                description:
                    - The git repo volume
                type: dict
                suboptions:
                    directory:
                        description:
                            - Target directory name
                        type: str
                    repository:
                        description:
                            - Repository URL
                        required: true
                        type: str
                    revision:
                        description:
                            - Commit hash for the specified revision
                        type: str
    force_update:
        description:
            - Force update of existing container instance. Any update will result in deletion and recreation of existing containers.
        type: bool
        default: 'no'

extends_documentation_fragment:
    - azure.azcollection.azure
    - azure.azcollection.azure_tags

author:
    - Zim Kalinowski (@zikalino)

'''

EXAMPLES = '''
  - name: Create sample container group
    azure_rm_containerinstance:
      resource_group: myResourceGroup
      name: myContainerInstanceGroup
      os_type: Linux
      ip_address: Public
      containers:
        - name: myContainer1
          image: httpd
          memory: 1.5
          ports:
            - 80
            - 81

  - name: Create sample container group with azure file share volume
    azure_rm_containerinstance:
      resource_group: myResourceGroup
      name: myContainerInstanceGroupz
      os_type: Linux
      ip_address: Public
      containers:
        - name: mycontainer1
          image: httpd
          memory: 1
          volume_mounts:
            - name: filesharevolume
              mount_path: "/data/files"
          ports:
            - 80
            - 81
      volumes:
        - name: filesharevolume
          azure_file:
            storage_account_name: mystorageaccount
            share_name: acishare
            storage_account_key: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

  - name: Create sample container group with git repo volume
    azure_rm_containerinstance:
      resource_group: myResourceGroup
      name: myContainerInstanceGroup
      os_type: Linux
      ip_address: Public
      containers:
        - name: mycontainer1
          image: httpd
          memory: 1
          volume_mounts:
            - name: myvolume1
              mount_path: "/mnt/test"
          ports:
            - 80
            - 81
      volumes:
        - name: myvolume1
          git_repo:
            repository: "https://github.com/Azure-Samples/aci-helloworld.git"

  - name: Disable required SSL for keycloak container
    azure_rm_containerinstance:
      resource_group: "myResourceGroup"
      name: "myContainerInstanceGroup"
      state: "execute"
      terminal:
        container: "myContainerInstance"
        lines:
          - 'cd $JBOSS_HOME/bin'
          - './kcadm.sh config credentials --server http://localhost:8080/auth --realm master --user admin'
          - 'mysecretpassword'
          - './kcadm.sh update realms/master -s sslRequired=NONE'

  - name: Restart containers group and wait 300 secondes
    azure_rm_containerinstance:
      resource_group: "myResourceGroup"
      name: "myContainerInstanceGroup"
      state: "restart"
      restart_wait: 300

'''
RETURN = '''
id:
    description:
        - Resource ID.
    returned: always
    type: str
    sample: /subscriptions/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/resourceGroups/myResourceGroup/providers/Microsoft.ContainerInstance/containerGroups/aci1b6dd89
provisioning_state:
    description:
        - Provisioning state of the container.
    returned: always
    type: str
    sample: Creating
ip_address:
    description:
        - Public IP Address of created container group.
    returned: if address is public
    type: str
    sample: 175.12.233.11
containers:
    description:
        - The containers within the container group.
    returned: always
    type: list
    elements: dict
    sample: [
                {
                    "commands": null,
                    "cpu": 1.0,
                    "environment_variables": null,
                    "image": "httpd",
                    "memory": 1.0,
                    "name": "mycontainer1",
                    "ports": [
                        80,
                        81
                    ],
                    "volume_mounts": [
                        {
                            "mount_path": "/data/files",
                            "name": "filesharevolume",
                            "read_only": false
                        }
                    ]
                }
    ]
volumes:
    description:
        - The list of volumes that mounted by containers in container group
    returned: if volumes specified
    type: list
    elements: dict
    contains:
        name:
            description:
                - The name of the Volume
            returned: always
            type: str
            sample: filesharevolume
        azure_file:
            description:
                - Azure file share volume details
            returned: If Azure file share type of volume requested
            type: dict
            sample: {
                        "read_only": null,
                        "share_name": "acishare",
                        "storage_account_key": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
                        "storage_account_name": "mystorageaccount"
            }
        empty_dir:
            description:
                - Empty directory volume details
            returned: If Empty directory type of volume requested
            type: dict
            sample: {}
        secret:
            description:
                - Secret volume details
            returned: If Secret type of volume requested
            type: dict
            sample: {}
        git_repo:
            description:
                - Git Repo volume details
            returned: If Git repo type of volume requested
            type: dict
            sample: {
                        "directory": null,
                        "repository": "https://github.com/Azure-Samples/aci-helloworld.git",
                        "revision": null
            }
console:
    description:
        - Terminal output
    returned: if state is execute
    type: list
state:
    description:
        - Restart opperation and result
    returned: if state is restart
    type: dict
'''
from ansible_collections.azure.azcollection.plugins.module_utils.azure_rm_common import AzureRMModuleBaseEx, AzureRMTerminal
from ansible.module_utils.common.dict_transformations import _snake_to_camel
from ansible.module_utils._text import to_native
import datetime

try:
    from msrestazure.azure_exceptions import CloudError
    #from msrest.polling import LROPoller
    from azure.core.polling import LROPoller
    from azure.core.exceptions import HttpResponseError
    from azure.mgmt.containerinstance import ContainerInstanceManagementClient
except ImportError:
    # This is handled in azure_rm_common
    pass


def create_container_dict_from_obj(container):
    '''
    Create a dict from an instance of a Container.

    :param rule: Container
    :return: dict
    '''
    results = dict(
        name=container.name,
        image=container.image,
        memory=container.resources.requests.memory_in_gb,
        cpu=container.resources.requests.cpu
        # command (list of str)
        # ports (list of ContainerPort)
        # environment_variables (list of EnvironmentVariable)
        # resources (ResourceRequirements)
        # volume mounts (list of VolumeMount)
    )

    if container.instance_view is not None:
        # instance_view (ContainerPropertiesInstanceView)
        results["instance_restart_count"] = container.instance_view.restart_count
        if container.instance_view.current_state:
            results["instance_current_state"] = container.instance_view.current_state.state
            results["instance_current_start_time"] = container.instance_view.current_state.start_time
            results["instance_current_exit_code"] = container.instance_view.current_state.exit_code
            results["instance_current_finish_time"] = container.instance_view.current_state.finish_time
            results["instance_current_detail_status"] = container.instance_view.current_state.detail_status
        if container.instance_view.previous_state:
            results["instance_previous_state"] = container.instance_view.previous_state.state
            results["instance_previous_start_time"] = container.instance_view.previous_state.start_time
            results["instance_previous_exit_code"] = container.instance_view.previous_state.exit_code
            results["instance_previous_finish_time"] = container.instance_view.previous_state.finish_time
            results["instance_previous_detail_status"] = container.instance_view.previous_state.detail_status
        # events (list of ContainerEvent)
    return results


env_var_spec = dict(
    name=dict(type='str', required=True),
    value=dict(type='str', required=True),
    is_secure=dict(type='bool')
)


volume_mount_var_spec = dict(
    name=dict(type='str', required=True),
    mount_path=dict(type='str', required=True),
    read_only=dict(type='bool')
)

port_spec = dict(
    port=dict(type='int', required=True),
    protocol=dict(
        type='str', 
        default='TCP',
        choices=["TCP", "UDP"]
    )
)

container_spec = dict(
    name=dict(type='str', required=True),
    image=dict(type='str', required=True),
    memory=dict(type='float', default=1.5),
    cpu=dict(type='float', default=1),
    ports=dict(type='list', elements='dict', options=port_spec),
    commands=dict(type='list', elements='str'),
    environment_variables=dict(type='list', elements='dict', options=env_var_spec),
    volume_mounts=dict(type='list', elements='dict', options=volume_mount_var_spec)
)


git_repo_volume_spec = dict(
    directory=dict(type='str'),
    repository=dict(type='str', required=True),
    revision=dict(type='str')
)


azure_file_volume_spec = dict(
    share_name=dict(type='str', required=True),
    read_only=dict(type='bool'),
    storage_account_name=dict(type='str', required=True),
    storage_account_key=dict(type='str', required=True, no_log=True)
)

subnet_spec = dict(
    name=dict(type='str'),
    vnet=dict(type='str', required=True),
    subnet=dict(type='str', required=True)
)

volumes_spec = dict(
    name=dict(type='str', required=True),
    azure_file=dict(type='dict', options=azure_file_volume_spec),
    empty_dir=dict(type='dict'),
    secret=dict(type='dict', no_log=True),
    git_repo=dict(type='dict', options=git_repo_volume_spec)
)

terminal_spec = dict(
    container=dict(type='str',required=True),
    command=dict(type='str',default='/bin/sh'),
    lines=dict(type='list',elements='str',required=True),
    wait_timeout=dict(type='int',default=120),
    wait_regex=dict(type='str',default='[#$:] $'),
    fail_on_timeout=dict(type='bool',default=True)
)

class AzureRMContainerInstance(AzureRMModuleBaseEx):
    """Configuration class for an Azure RM container instance resource"""

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
            os_type=dict(
                type='str',
                default='Linux',
                choices=['Linux', 'Windows']
            ),
            state=dict(
                type='str',
                default='present',
                choices=['present', 'absent','restart','execute']
            ),
            location=dict(
                type='str',
            ),
            ip_address=dict(
                type='str',
                default='none',
                choices=['Public', 'Private' ,'none']
            ),
            subnets=dict(
                type='list',
                elements='dict',
                options=subnet_spec,
                default=[],
            ),
            dns_name_label=dict(
                type='str',
            ),
            ports=dict(
                type='list',
                elements='dict',
                options=port_spec,
                default=[],
            ),
            registry_login_server=dict(
                type='str',
                default=None
            ),
            registry_username=dict(
                type='str',
                default=None
            ),
            registry_password=dict(
                type='str',
                default=None,
                no_log=True
            ),
            containers=dict(
                type='list',
                elements='dict',
                options=container_spec
            ),
            restart_policy=dict(
                type='str',
                choices=['always', 'on_failure', 'never']
            ),
            force_update=dict(
                type='bool',
                default=False
            ),
            volumes=dict(
                type='list',
                elements='dict',
                options=volumes_spec
            ),
            restart_wait=dict(
                type='int',
                default=None
            ),
            terminal=dict(
                type='dict', 
                options=terminal_spec,
                default=None
            )
        )

        self.resource_group = None
        self.name = None
        self.location = None
        self.state = None
        self.ip_address = None
        self.subnets = None
        self.dns_name_label = None
        self.containers = None
        self.restart_policy = None
        self.restart_wait = None

        self.tags = None

        self.results = dict(changed=False, state=dict())
        self.cgmodels = None

        required_if = [
            ('state', 'present', ['containers']),
            ('state', 'execute', ['terminal']),
            ('ip_address', 'Private', ['subnets'])
        ]
        mutually_exclusive = [['containers', 'terminal'],['subnets','dns_name_label']]

        super(AzureRMContainerInstance, self).__init__(derived_arg_spec=self.module_arg_spec,
                                                       mutually_exclusive=mutually_exclusive,
                                                       supports_check_mode=True,
                                                       supports_tags=True,
                                                       required_if=required_if)

    def exec_module(self, **kwargs):
        """Main module execution method"""

        for key in list(self.module_arg_spec.keys()) + ['tags']:
            setattr(self, key, kwargs[key])

        resource_group = None
        response = None

        # since this client hasn't been upgraded to expose models directly off the OperationClass, fish them out
        self.cgmodels = self.containerinstance_client.container_groups.models

        resource_group = self.get_resource_group(self.resource_group)

        if not self.location:
            self.location = resource_group.location

        response = self.get_containerinstance()

        if not response:
            self.log("Container Group doesn't exist")

            if self.state == 'absent':
                self.log("Nothing to delete")
            elif self.state == 'restart':
                self.log("Nothing to restart")
            elif self.state == 'execute':
                self.log("Container Group doesn't exist")
            else:
                self.force_update = True
        else:
            self.log("Container instance already exists")

            if self.state == 'absent':
                if not self.check_mode:
                    self.delete_containerinstance()
                self.results['changed'] = True
                self.log("Container instance deleted")
            elif self.state == 'present':
                self.log("Need to check if container group has to be deleted or may be updated")
                oldtags = response.tags.as_dict() if response.tags else None
                update_tags, newtags = self.update_tags(oldtags)
                if update_tags:
                    self.tags = newtags

                if self.force_update:
                    self.log('Deleting container instance before update')
                    if not self.check_mode:
                        self.delete_containerinstance()

        if self.state == 'present':

            self.log("Need to Create / Update the container instance")

            new_container = self.new_containerinstance()

            if self.force_update:
                self.results['changed'] = True
                if self.check_mode:
                    return self.results
                response = self.create_update_containerinstance(new_container)
            elif self.compare(new_container, response):
                self.results['changed'] = True
                if self.check_mode:
                    return self.results
                response = self.create_update_containerinstance(new_container)

            if not isinstance(response, dict):
                response = response.as_dict()
            self.results['id'] = response['id']
            self.results['provisioning_state'] = response['provisioning_state']
            self.results['ip_address'] = response['ip_address']['ip'] if 'ip_address' in response else ''

            self.log("Creation / Update done")
        elif self.state == 'execute':

            self.log("Excute commande in container instance")
            self.execute_containerinstance(response)
            self.results['changed'] = True

        elif self.state == 'restart':

            self.log("Restart the container instance")

            response = self.restart_containerinstance(response)
            if self.restart_wait is None:
                self.results['changed'] = True
            elif response == 'Succeeded':
                self.results['changed'] = True
            else:
                self.fail("Error when restarting containers: {0}".format(response))

        return self.results

    def execute_containerinstance(self, response):
        self.log("Execute in container instance {0}.{1}".format(self.name, self.terminal['container']))
        terminal = None
        try:
            execRequest = self.cgmodels.ContainerExecRequest(command=self.terminal['command'], terminal_size={"rows": 12,"cols": 200})
            execResponse = self.containerinstance_client.containers.execute_command(
                    resource_group_name=self.resource_group, container_group_name=self.name, 
                    container_name=self.terminal['container'], container_exec_request=execRequest)
            
            terminal = AzureRMTerminal(execResponse, self.terminal)
            terminal.execute(self.terminal['lines'])
            self.results['console'] = terminal.console

        except (CloudError, HttpResponseError) as exc:
            self.fail("Error when restarting containers group {0}: {1}".format(self.name, exc.message or str(exc)))
        finally:
            if terminal is not None:
                terminal.close()

    def restart_containerinstance(self, response):
        self.log("Restart the container instance {0}".format(self.name))
        try:
            state_name = 'restart'
            if response.instance_view.state == 'Running':
                poller = self.containerinstance_client.container_groups.begin_restart(resource_group_name=self.resource_group, container_group_name=self.name)
            else:
                state_name = 'start'
                poller = self.containerinstance_client.container_groups.begin_start(resource_group_name=self.resource_group, container_group_name=self.name)
            if self.restart_wait is not None:
                poller.wait(self.restart_wait)
                if not poller.done():
                    return 'time-out'
            self.results['state'][state_name] = poller.status()
            return poller.status()
        except (CloudError, HttpResponseError) as exc:
            self.fail("Error when restarting containers group {0}: {1}".format(self.name, exc.message or str(exc)))

    def new_containerinstance(self):
        '''
        Creates a container service model with the specified configuration of orchestrator, masters, and agents.

        :return: the desired container instance model
        '''
        self.log("New container instance {0}".format(self.name))

        registry_credentials = None

        if self.registry_login_server is not None:
            registry_credentials = [self.cgmodels.ImageRegistryCredential(server=self.registry_login_server,
                                                                          username=self.registry_username,
                                                                          password=self.registry_password)]

        ip_address = None

        containers = []
        all_ports = dict()
        for container_def in self.containers:
            name = container_def.get("name")
            image = container_def.get("image")
            memory = container_def.get("memory")
            cpu = container_def.get("cpu")
            commands = container_def.get("commands")
            ports = []
            variables = []
            volume_mounts = []

            port_list = container_def.get("ports")
            if port_list:
                for port in port_list:
                    all_ports[port['port']] = port
                    ports.append(self.cgmodels.ContainerPort(port=port['port'],protocol=port['protocol']))

            variable_list = container_def.get("environment_variables")
            if variable_list:
                for variable in variable_list:
                    variables.append(self.cgmodels.EnvironmentVariable(name=variable.get('name'),
                                                                       value=variable.get('value') if not variable.get('is_secure') else None,
                                                                       secure_value=variable.get('value') if variable.get('is_secure') else None))

            volume_mounts_list = container_def.get("volume_mounts")
            if volume_mounts_list:
                for volume_mount in volume_mounts_list:
                    volume_mounts.append(self.cgmodels.VolumeMount(name=volume_mount.get('name'),
                                                                   mount_path=volume_mount.get('mount_path'),
                                                                   read_only=volume_mount.get('read_only')))

            containers.append(self.cgmodels.Container(name=name,
                                                      image=image,
                                                      resources=self.cgmodels.ResourceRequirements(
                                                          requests=self.cgmodels.ResourceRequests(memory_in_gb=memory, cpu=cpu)
                                                      ),
                                                      ports=ports,
                                                      command=commands,
                                                      environment_variables=variables,
                                                      volume_mounts=volume_mounts))

        if self.ip_address == 'Public' or self.ip_address == 'Private':
            # get list of ports
            if all_ports:
                ports = []
                for key in all_ports.keys():
                    port = all_ports[key]
                    ports.append(self.cgmodels.Port(port=port['port'], protocol=port['protocol']))
                ip_address = self.cgmodels.IpAddress(ports=ports, dns_name_label=self.dns_name_label, type=self.ip_address)
                if self.ip_address == 'Private':
                    subnets = [self.cgmodels.ContainerGroupSubnetId(
                        name=item.get('name'),
                        id=subnet_id(self.subscription_id,
                                        self.resource_group,
                                        item.get('vnet'),
                                        item.get('subnet'))
                    ) for item in self.subnets] if self.subnets else None

        volumes = [self.cgmodels.Volume(
            name=item.get('name'),
            azure_file=self.cgmodels.AzureFileVolume(
                share_name=item["azure_file"].get('share_name'),
                read_only=item["azure_file"].get('read_only'),
                storage_account_name=item["azure_file"].get('storage_account_name'),
                storage_account_key=item["azure_file"].get('storage_account_key')
            )
        ) for item in self.volumes] if self.volumes else None
                
        parameters = self.cgmodels.ContainerGroup(containers=containers,
                                                  os_type=self.os_type,
                                                  location=self.location,
                                                  tags=self.tags,
                                                  zones=None,
                                                  identity=None,
                                                  image_registry_credentials=registry_credentials,
                                                  restart_policy=_snake_to_camel(self.restart_policy, True) if self.restart_policy else None,
                                                  ip_address=ip_address,
                                                  volumes=volumes,
                                                  diagnostics=None,
                                                  subnet_ids=subnets,
                                                  dns_config=None,
                                                  sku=None,
                                                  encryption_properties=None,
                                                  init_containers=None)

        return parameters

    def compare(self, new_container, old_container):
        old_container = self.assign_account_key(new_container, old_container)
        new_container = self.object_assign(new_container, old_container)
        if not default_compare(new_container.as_dict(), old_container.as_dict(), ''):
            changed = True
        else:
            changed = False
        return changed

    def assign_account_key(self, patch, origin):
        attribute_map = ['volumes']
        for attribute in attribute_map:
            properties = getattr(patch, attribute)
            if not properties:
                continue
            references = getattr(origin, attribute) if origin else []
            for item in properties:
                if not item.azure_file:
                    continue
                refs = [x for x in references if to_native(x.name) == item.name]
                ref = refs[0] if len(refs) > 0 else None
                ref.azure_file.storage_account_key  = item.azure_file.storage_account_key if ref else None
        return origin

    def object_assign(self, patch, origin):
        attribute_map = set(self.cgmodels.ContainerGroup._attribute_map.keys()) - set(self.cgmodels.ContainerGroup._validation.keys())
        for key in attribute_map:
            if not getattr(patch, key):
                setattr(patch, key, getattr(origin, key))
        return patch

    def create_update_containerinstance(self, parameters):
        '''
        Creates or updates a container service with the specified configuration of orchestrator, masters, and agents.

        :return: deserialized container instance state dictionary
        '''
        self.log("Creating / Updating the container instance {0}".format(self.name))

        try:

            retry = 0

            while True:
                #2021-12-12T17:19:53+00:00
                now = datetime.datetime.utcnow()
                #now = now.strftime('%Y-%m-%dT%H:%M:%S+00:00')
                now = int(now.strftime('%Y%m%d%H%M%S'))

                response = self.containerinstance_client.container_groups.begin_create_or_update(resource_group_name=self.resource_group,
                                                                                                container_group_name=self.name,
                                                                                                container_group=parameters)
                if isinstance(response, LROPoller):
                    while not response.done():
                        response.wait(15)
                        container = self.get_containerinstance()
                        if container:
                            refs = [x for x in container.instance_view.events if self.is_doa_event(now, x)]
                            if len(refs) > 0:
                                self.containerinstance_client.container_groups.stop(resource_group_name=self.resource_group, container_group_name=self.name)
                                retry += 1
                                if retry == 3:
                                    ref = refs[len(refs) - 1] # if len(refs) > 0 else None
                                    self.fail("Error when creating ACI {0}: {1}-{2}".format(self.name, ref.name, ref.message))
                                break  # while not response.done()
                    if response.done():
                        response = response.result()
                        return response.as_dict()
        except (CloudError, HttpResponseError) as exc:
            self.fail("Error when creating ACI {0}: {1}".format(self.name, exc.message or str(exc)))

        return None

    def is_doa_event(self, timeRef, event):
        if event.type == "Normal":
            return False
        if event.message and "timeout" in event.message.lower():
            return False
        last_timestamp = int(event.last_timestamp.strftime('%Y%m%d%H%M%S'))
        self.log("Test event: {0} < {1} == {2}".format(timeRef, last_timestamp, timeRef < last_timestamp))
        if timeRef < last_timestamp:
            return True
        return False

    def delete_containerinstance(self):
        '''
        Deletes the specified container group instance in the specified subscription and resource group.

        :return: True
        '''
        self.log("Deleting the container instance {0}".format(self.name))
        try:
            response = self.containerinstance_client.container_groups.begin_delete(resource_group_name=self.resource_group, container_group_name=self.name)
            return True
        except (CloudError, HttpResponseError) as exc:
            self.fail('Error when deleting ACI {0}: {1}'.format(self.name, exc.message or str(exc)))
            return False

    def get_containerinstance(self):
        '''
        Gets the properties of the specified container service.

        :return: deserialized container instance state dictionary
        '''
        self.log("Checking if the container instance {0} is present".format(self.name))
        found = False
        try:
            response = self.containerinstance_client.container_groups.get(resource_group_name=self.resource_group, container_group_name=self.name)
            found = True
            self.log("Response : {0}".format(response))
            self.log("Container instance : {0} found".format(response.name))
        except HttpResponseError as e:
            if e.status_code == 404:
                self.log('Did not find the container instance.')
            else:
                raise e
        except CloudError as e:
            self.log('Did not find the container instance.')
        if found is True:
            return response

        return False

def subnet_id(subscription_id, resource_group_name, virtual_network_name, name):
    """Generate the id for a subnet in a virtual network"""
    return '/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Network/virtualNetworks/{2}/subnets/{3}'.format(
        subscription_id,
        resource_group_name,
        virtual_network_name,
        name
    )

def default_compare(new, old, path):
    if isinstance(new, dict):
        if not isinstance(old, dict):
            return False
        for k in new.keys():
            if not default_compare(new.get(k), old.get(k, None), path + '/' + k):
                return False
        return True
    elif isinstance(new, list):
        if not isinstance(old, list) or len(new) != len(old):
            return False
        if len(old) == 0:
            return True
        if isinstance(old[0], dict):
            key = None
            if 'id' in old[0] and 'id' in new[0]:
                key = 'id'
            elif 'name' in old[0] and 'name' in new[0]:
                key = 'name'
            elif 'port' in old[0] and 'port' in new[0]:
                key = 'port'
            new = sorted(new, key=lambda x: x.get(key, None))
            old = sorted(old, key=lambda x: x.get(key, None))
        else:
            new = sorted(new)
            old = sorted(old)
        for i in range(len(new)):
            if not default_compare(new[i], old[i], path + '/*'):
                return False
        return True
    else:
        return new == old

def main():
    """Main execution"""
    AzureRMContainerInstance()


if __name__ == '__main__':
    main()
