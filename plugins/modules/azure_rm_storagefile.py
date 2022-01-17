#!/usr/bin/python
#
# Copyright (c) 2016 Matt Davis, <mdavis@ansible.com>
#                    Chris Houseknecht, <house@redhat.com>
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
from traceback import print_exc
__metaclass__ = type


DOCUMENTATION = '''
---
module: azure_rm_storagefile
short_description: Manage file shares and file objects
version_added: "0.0.1"
description:
    - Create, update and delete file shares and file objects.
    - Use to upload a file and store it as a file object, or download a file object to a file(upload and download mode)
    - Use to upload a batch of files under a given directory(batch upload mode)
    - In the batch upload mode, the existing file object will be overwritten if a file object with the same name is to be created.
    - the module can work exclusively in three modes, when C(batch_upload_src) is set, it is working in batch upload mode;
      when C(src) is set, it is working in upload mode and when C(dst) is set, it is working in dowload mode.
options:
    storage_account_name:
        description:
            - Name of the storage account to use.
        required: true
        aliases:
            - account_name
            - storage_account
    file:
        description:
            - Name of a file object within the share.
        aliases:
            - file_name
    share:
        description:
            - Name of a file share within the storage account.
        required: true
        aliases:
            - share_name
    content_type:
        description:
            - Set the file content-type header. For example C(image/png).
    cache_control:
        description:
            - Set the file cache-control header.
    content_disposition:
        description:
            - Set the file content-disposition header.
    content_encoding:
        description:
            - Set the file encoding header.
    content_language:
        description:
            - Set the file content-language header.
    content_md5:
        description:
            - Set the file md5 hash value.
    dest:
        description:
            - Destination file path. Use with state C(present) to download a file.
        aliases:
            - destination
    force:
        description:
            - Overwrite existing file or file when uploading or downloading. Force deletion of a share that contains files.
        type: bool
        default: no
    resource_group:
        description:
            - Name of the resource group to use.
        required: true
        aliases:
            - resource_group_name
    src:
        description:
            - Source file path. Use with state C(present) to upload a file.
        aliases:
            - source
    state:
        description:
            - State of a share or file.
            - Use state C(absent) with a share value only to delete a share. Include a file value to remove
              a specific file. A share will not be deleted, if it contains files. Use the I(force) option to override,
              deleting the share and all associated files.
            - Use state C(present) to create or update a share and upload or download a file. If the share
              does not exist, it will be created. If it exists, it will be updated with configuration options. Provide
              a file name and either src or dest to upload or download. Provide a src path to upload and a dest path
              to download. If a file (uploading) or a file (downloading) already exists, it will not be overwritten
              unless I(force=true).
        default: present
        choices:
            - absent
            - present

extends_documentation_fragment:
    - azure.azcollection.azure
    - azure.azcollection.azure_tags

author:
    - Chris Houseknecht (@chouseknecht)
    - Matt Davis (@nitzmahone)

'''

EXAMPLES = '''
- name: Remove share foo
  azure_rm_storagefile:
    resource_group: myResourceGroup
    storage_account_name: clh0002
    share_name: foo
    state: absent

- name: Create share foo and upload a file
  azure_rm_storagefile:
    resource_group: myResourceGroup
    storage_account_name: clh0002
    share_name: foo
    file: graylog.png
    src: ./files/graylog.png
    content_type: 'application/image'


- name: Upload file from template in share foo
  azure_rm_storagefile:
    resource_group: myResourceGroup
    storage_account_name: clh0002
    share_name: foo
    file_path: index.html
    template: "{{ lookup('template', 'index.html.j2') }}"
    content_type: 'text/html'

- name: Download the file
  azure_rm_storagefile:
    resource_group: myResourceGroup
    storage_account_name: clh0002
    share_name: foo
    file: graylog.png
    dest: ~/tmp/images/graylog.png

- name: Create directory in share foo
  azure_rm_storagefile:
    resource_group: myResourceGroup
    storage_account_name: clh0002
    share_name: foo
    file: dir1/sub1/sub2
'''

RETURN = '''
file:
    description:
        - Facts about the current state of the file.
    returned: when a file is operated on
    type: dict
    sample: {
        "content_length": 136532,
        "content_settings": {
            "cache_control": null,
            "content_disposition": null,
            "content_encoding": null,
            "content_language": null,
            "content_md5": null,
            "content_type": "application/image"
        },
        "last_modified": "09-Mar-2016 22:08:25 +0000",
        "name": "graylog.png",
        "tags": {},
        "type": "BlockFile"
    }
container:
    description:
        - Facts about the current state of the selected container.
    returned: always
    type: dict
    sample: {
        "last_modified": "09-Mar-2016 19:28:26 +0000",
        "name": "foo",
        "tags": {}
    }
'''

import os
import mimetypes
import hashlib

try:
    from azure.storage.file.models import ContentSettings
    from azure.common import AzureMissingResourceHttpError, AzureHttpError
except ImportError:
    # This is handled in azure_rm_common
    pass

from ansible_collections.azure.azcollection.plugins.module_utils.azure_rm_common import AzureRMModuleBase


class AzureRMStorageFile(AzureRMModuleBase):

    def __init__(self):

        self.module_arg_spec = dict(
            resource_group=dict(required=True, type='str', aliases=['resource_group_name']),
            storage_account_name=dict(required=True, type='str', aliases=['account_name', 'storage_account']),
            share_name=dict(required=True, type='str', aliases=['share']),
            quota=dict(type='int'),
            src=dict(type='str', aliases=['source_file']),
            template=dict(type='str'),
            file=dict(type='path', aliases=['file_path']),
            dest=dict(type='path', aliases=['destination']),
            force=dict(type='bool', default=False),
            state=dict(type='str', default='present', choices=['absent', 'present']),
            content_type=dict(type='str'),
            content_encoding=dict(type='str'),
            content_language=dict(type='str'),
            content_disposition=dict(type='str'),
            cache_control=dict(type='str'),
            content_md5=dict(type='str'),
        )

        mutually_exclusive = [('src', 'dest','template')]

        self.storage_account_name = None
        self.share_name = None
        self.share_obj = None
        self.quota = None
        self.file = None
        self.file_path = None
        self.file_name = None
        self.directory_path = None
        self.file_obj = None
        self.dir_obj = None
        self.dest = None
        self.force = None
        self.resource_group = None
        self.src = None
        self.template = None
        self.state = None
        self.tags = None
        self.results = dict(
            changed=False,
            actions=[],
            file=dict()
        )

        super(AzureRMStorageFile, self).__init__(derived_arg_spec=self.module_arg_spec,
                                                 supports_check_mode=True,
                                                 mutually_exclusive=mutually_exclusive,
                                                 supports_tags=True)

    def exec_module(self, **kwargs):

        for key in list(self.module_arg_spec.keys()) + ['tags']:
            setattr(self, key, kwargs[key])

        self.results['check_mode'] = self.check_mode

        if self.file:
            # add file path validation
            self.file = self.file.strip('/')
            self.file_path = self.file.split('/')
            self.file_name = self.file_path[-1]
            self.directory_path = "/".join(self.file_path[:-1])

        self.file_client = self.get_file_client(self.resource_group, self.storage_account_name)
        self.share_obj = self.get_share()
        
        if self.state == 'present':
            if self.file:
                if not self.share_obj:
                    self.results['changed'] = self.file_client.create_share(self.share_name, None, self.quota)
                if self.src or self.template:
                    # create, update or download file
                    self.file_obj = self.get_file()
                    if self.src and self.src_is_valid():
                        if self.file_obj and not self.force:
                            self.log("Cannot upload to {0}. File with that name already exists. "
                                    "Use the force option".format(self.file))
                        else:
                            self.upload_file()
                    elif self.template:
                        if self.file_obj and not self.force:
                            self.log("Cannot upload to {0}. File with that name already exists. "
                                    "Use the force option".format(self.file))
                        else:
                            self.upload_file(True)
                elif self.dest and self.dest_is_valid():
                    self.download_file()
                elif self.file:
                    self.dir_obj = self.get_directory()
                    if not self.dir_obj:
                        self.file_obj = self.get_file()
                    if self.file_obj:
                        # juste return file info
                        None
                        #self.fail("Cannot create directory {0}. File with that name already exists.".format(self.file))
                    elif not self.dir_obj:
                        self.create_directory()

                if self.file_obj:
                    update_tags, self.file_obj['tags'] = self.update_tags(self.file_obj.get('tags'))
                    if update_tags:
                        self.update_file_tags(self.file_obj['tags'])

                    if self.file_content_settings_differ():
                        self.update_file_content_settings()
                elif self.dir_obj:
                    update_tags, self.dir_obj['tags'] = self.update_tags(self.dir_obj.get('tags'))
                    if update_tags:
                        self.update_directory_tags(self.dir_obj['tags'])
            else:
                if not self.share_obj:
                    self.results['changed'] = self.file_client.create_share(self.share_name, self.tags, self.quota)
                else:
                    if self.quota and self.share_obj.properties.quota != self.quota:
                        self.file_client.set_share_properties(self.share_name, self.quota)
                        self.results['changed'] = True
                    update_tags, tags = self.update_tags(self.share_obj.get('tags'))
                    if update_tags:
                        self.file_client.set_share_metadata(self.share_name, tags)
                        self.results['changed'] = True

        elif self.state == 'absent':
            if self.file:
                self.file_obj = self.get_file()
                if self.file_obj:
                    # Delete file
                    self.delete_file()
                else:
                    self.dir_obj = self.get_directory()
                    if self.dir_obj and self.force:
                        self.delete_directory()
                    elif not self.directory_has_files():
                        self.delete_directory()
                    else:
                        self.fail("Failed to delete directory {0}:{1}. It contains files. Use the force option.".format(self.share_name, self.file))
            elif self.force:
                self.delete_share()
            elif not self.share_has_files():
                self.delete_share()
            else:
                self.fail("Failed to delete share {0}. It contains files. Use the force option.".format(self.share_name))

        # until we sort out how we want to do this globally
        del self.results['actions']
        if not self.results['file'] and self.file_obj:
            self.results['file'] = self.file_obj
        return self.results


    def get_share(self):
        result = {}
        share = None
        if self.share_name:
            try:
                share = self.file_client.get_share_properties(self.share_name)
            except AzureMissingResourceHttpError:
                pass
        if share:
            result = dict(
                name=share.name,
                tags=share.metadata,
                last_modified=share.properties.last_modified.strftime('%d-%b-%Y %H:%M:%S %z'),
            )
        return result

    def get_file(self):
        result = dict()
        file = None
        if self.file:
            try:
                file = self.file_client.get_file_properties(self.share_name, self.directory_path, self.file_name)
            except AzureMissingResourceHttpError:
                pass
        if file:
            result = dict(
                name=file.name,
                tags=file.metadata,
                last_modified=file.properties.last_modified.strftime('%d-%b-%Y %H:%M:%S %z'),
                content_length=file.properties.content_length,
                content_settings=dict(
                    content_type=file.properties.content_settings.content_type,
                    content_encoding=file.properties.content_settings.content_encoding,
                    content_language=file.properties.content_settings.content_language,
                    content_disposition=file.properties.content_settings.content_disposition,
                    cache_control=file.properties.content_settings.cache_control,
                    content_md5=file.properties.content_settings.content_md5
                )
            )
        return result

    
    def get_directory(self):
        result = dict()
        dir = None
        if self.file:
            try:
                #get_directory_properties(self, share_name, directory_name
                dir = self.file_client.get_directory_properties(self.share_name, self.file)
            except AzureMissingResourceHttpError:
                pass
        if dir:
            result = dict(
                name=dir.name,
                tags=dir.metadata,
                last_modified=dir.properties.last_modified.strftime('%d-%b-%Y %H:%M:%S %z')
            )
        return result

    def calculate_md5(self):
        if self.template:
            return hashlib.md5(self.template.encode('utf-8')).hexdigest()

        with open(self.src, "rb") as file_to_check:
            data = file_to_check.read()
        return hashlib.md5(data).hexdigest()

    def upload_file(self, as_text=False):
        content_settings = None
        md5_returned = self.calculate_md5()
        md5_originale = None
        if self.file_obj:
            md5_originale = self.file_obj['content_settings']['content_md5']

        if self.content_type or self.content_encoding or self.content_language or self.content_disposition or \
                self.cache_control or md5_returned:
            content_settings = ContentSettings(
                content_type=self.content_type,
                content_encoding=self.content_encoding,
                content_language=self.content_language,
                content_disposition=self.content_disposition,
                cache_control=self.cache_control,
                content_md5=md5_returned
            )
        if not self.check_mode:
            try:
                self._create_directory()
                if as_text:
                    self.file_client.create_file_from_text(self.share_name, self.directory_path, self.file_name,
                                                           self.template, self.content_encoding,
                                                           content_settings=content_settings, metadata=self.tags)
                else:
                    self.file_client.create_file_from_path(self.share_name, self.directory_path, self.file_name,
                                                        self.src,
                                                        content_settings=content_settings, metadata=self.tags)
            except AzureHttpError as exc:
                self.fail("Error creating file {0} - {1}".format(self.file, str(exc)))

        self.file_obj = self.get_file()
        self.results['changed'] = md5_originale != md5_returned
        self.results['actions'].append('created file {0} from {1}'.format(self.file, self.src))
        self.results['file'] = self.file_obj

    def create_directory(self):
        self._create_directory()
        self.file_client.create_directory(self.share_name, self.file)

    def _create_directory(self):
        path = ''
        for i in range(0,len(self.file_path) - 1):
            path += self.file_path[i]
            self.file_client.create_directory(self.share_name, path)
            path += '/'

    def download_file(self):
        if not self.check_mode:
            try:
                #share_name, directory_name, file_name, file_path,
                self.file_client.get_file_to_path(self.share_name, self.directory_path, self.file_name, self.dest)
            except Exception as exc:
                self.fail("Failed to download file {0}:{1} to {2} - {3}".format(self.share_name,
                                                                                self.file,
                                                                                self.dest,
                                                                                exc))
        self.results['changed'] = True
        self.results['actions'].append('downloaded file {0}:{1} to {2}'.format(self.share_name,
                                                                               self.file,
                                                                               self.dest))

        self.results['file'] = self.file_obj

    def src_is_valid(self):
        if not os.path.isfile(self.src):
            self.fail("The source path must be a file.")
        if os.access(self.src, os.R_OK):
            return True
        self.fail("Failed to access {0}. Make sure the file exists and that you have "
                  "read access.".format(self.src))

    def dest_is_valid(self):
        if not self.check_mode:
            if not os.path.basename(self.dest):
                # dest is a directory
                if os.path.isdir(self.dest):
                    self.log("Path is dir. Appending file name.")
                    self.dest += self.file
                else:
                    try:
                        self.log('Attempting to makedirs {0}'.format(self.dest))
                        os.makedirs(self.dest)
                    except IOError as exc:
                        self.fail("Failed to create directory {0} - {1}".format(self.dest, str(exc)))
                    self.dest += self.file
            else:
                # does path exist without basename
                file_name = os.path.basename(self.dest)
                path = self.dest.replace(file_name, '')
                self.log('Checking path {0}'.format(path))
                if not os.path.isdir(path):
                    try:
                        self.log('Attempting to makedirs {0}'.format(path))
                        os.makedirs(path)
                    except IOError as exc:
                        self.fail("Failed to create directory {0} - {1}".format(path, str(exc)))
            self.log('Checking final path {0}'.format(self.dest))
            if os.path.isfile(self.dest) and not self.force:
                # dest already exists and we're not forcing
                self.log("Dest {0} already exists. Cannot download. Use the force option.".format(self.dest))
                return False
        return True

    def delete_share(self):
        if not self.check_mode:
            try:
                #share_name, directory_name, file_name, timeout=None)
                self.file_client.delete_share(self.share_name)
            except AzureHttpError as exc:
                self.fail("Error deleting share {0}:{1}".format(self.share_name, str(exc)))

        self.results['changed'] = True
        self.results['actions'].append('deleted share {0}'.format(self.share_name))

    def directory_has_files(self):
        try:
            list_generator = self.file_client.list_directories_and_files(self.share_name, self.file)
        except AzureHttpError as exc:
            self.fail("Error list files in {0} - {1}".format(self.share_name, str(exc)))
        if len(list_generator.items) > 0:
            return True
        return False

    def share_has_files(self):
        try:
            list_generator = self.file_client.list_directories_and_files(self.share_name)
        except AzureHttpError as exc:
            self.fail("Error list files in {0} - {1}".format(self.share_name, str(exc)))
        if len(list_generator.items) > 0:
            return True
        return False

    def delete_file(self):
        if not self.check_mode:
            try:
                #share_name, directory_name, file_name, timeout=None)
                self.file_client.delete_file(self.share_name, self.directory_path, self.file_name)
            except AzureHttpError as exc:
                self.fail("Error deleting file {0}:{1} - {2}".format(self.share_name, self.file, str(exc)))

        self.results['changed'] = True
        self.results['actions'].append('deleted file {0}:{1}'.format(self.share_name, self.file))

    def update_file_tags(self, tags):
        if not self.check_mode:
            try:
                self.file_client.set_file_metadata(self.share_name, self.directory_path, self.file_name)
            except AzureHttpError as exc:
                self.fail("Update file tags {0}:{1} - {2}".format(self.share_name, self.file, str(exc)))
        self.file_obj = self.get_file()
        self.results['changed'] = True
        self.results['actions'].append("updated file {0}:{1} tags.".format(self.share_name, self.file))
        self.results['file'] = self.file_obj


    def update_directory_tags(self, tags):
        if not self.check_mode:
            try:
                self.file_client.set_directory_metadata(self.share_name, self.file, metadata=tags)
            except AzureHttpError as exc:
                self.fail("Update directory tags {0}:{1} - {2}".format(self.share_name, self.file, str(exc)))
        self.dir_obj = self.get_directory()
        self.results['changed'] = True
        self.results['actions'].append("updated directory {0}:{1} tags.".format(self.share_name, self.file))
        self.results['directory'] = self.dir_obj

    def file_content_settings_differ(self):
        if self.content_type or self.content_encoding or self.content_language or self.content_disposition or \
                self.cache_control or self.content_md5:
            settings = dict(
                content_type=self.content_type,
                content_encoding=self.content_encoding,
                content_language=self.content_language,
                content_disposition=self.content_disposition,
                cache_control=self.cache_control,
                content_md5=self.content_md5
            )
            if self.file_obj['content_settings'] != settings:
                return True

        return False

    def update_file_content_settings(self):
        content_settings = ContentSettings(
            content_type=self.content_type,
            content_encoding=self.content_encoding,
            content_language=self.content_language,
            content_disposition=self.content_disposition,
            cache_control=self.cache_control,
            content_md5=self.content_md5
        )
        if not self.check_mode:
            try:
                self.file_client.set_file_properties(self.share_name, self.directory_path, self.file_name, content_settings=content_settings)
            except AzureHttpError as exc:
                self.fail("Update file content settings {0}:{1} - {2}".format(self.share_name, self.file, str(exc)))

        self.file_obj = self.get_file()
        self.results['changed'] = True
        self.results['actions'].append("updated file {0}:{1} content settings.".format(self.share_name, self.file))
        self.results['file'] = self.file_obj


def main():
    AzureRMStorageFile()


if __name__ == '__main__':
    main()
