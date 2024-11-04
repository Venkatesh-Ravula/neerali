#!/usr/bin/python

# -*- coding: utf-8 -*-

from ansible.module_utils.basic import AnsibleModule
from ibm_cloud_sdk_core.api_exception import ApiException

# Import the class from the provided code

from ansible_collections.neerali.plugins.module_utils.ceph_vm_ibmvpc import CephVMNodeIBMVPC

DOCUMENTATION = '''
---
module: get_ibm_volumes_facts
short_description: Retrieve IBM Cloud VPC volumes information for a specified instance.
description:
  - This module retrieves and returns volume details for an IBM Cloud VPC instance.
options:
  access_key:
    description:
      - IBM Cloud API access key.
    required: true
    type: str
  service_url:
    description:
      - Endpoint URL for the IBM Cloud VPC service.
    required: true
    type: str
  instance_id:
    description:
      - The ID of the VPC instance.
    required: true
    type: str
'''

EXAMPLES = '''
# Retrieve volumes information for a specified instance
- name: Get volumes for IBM Cloud VPC instance
  get_ibm_volumes_facts:
    access_key: "your_ibm_access_key"
    service_url: "https://us-south.iaas.cloud.ibm.com/v1"
    instance_id: "instance_id_here"
  register: result
'''

RETURN = '''
volumes:
    description: List of volumes attached to the IBM Cloud VPC instance.
    type: list
    elements: dict
    returned: always
'''

def run_module():
    # Define module arguments
    module_args = dict(
        access_key=dict(type='str', required=True),
        service_url=dict(type='str', required=True),
        instance_id=dict(type='str', required=True),
    )

    # Initialize the module
    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    # Collect input parameters
    access_key = module.params['access_key']
    service_url = module.params['service_url']
    instance_id = module.params['instance_id']

    # Initialize the IBM Cloud VPC instance handler
    try:
        vm_node = CephVMNodeIBMVPC(access_key=access_key, service_url=service_url, vsi_id=instance_id)
    except ApiException as e:
        module.fail_json(msg=f"Failed to authenticate or initialize VPC service: {str(e)}")

    # Gather volume information
    try:
        volumes = vm_node.volumes
        result = dict(
            changed=False,
            volumes=volumes
        )
        module.exit_json(**result)
    except ApiException as e:
        module.fail_json(msg=f"Failed to retrieve volume information: {str(e)}")

def main():
    run_module()

if __name__ == '__main__':
    main()