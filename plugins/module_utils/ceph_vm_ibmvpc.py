#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os
import re
import socket
from copy import deepcopy
from datetime import datetime, timedelta
from time import sleep
from typing import Any, Dict, List, Optional
from ibm_vpc import VpcV1
from ibm_cloud_sdk_core.authenticators import IAMAuthenticator
from ibm_cloud_sdk_core.api_exception import ApiException
from ibm_platform_services.iam_identity_v1 import IamIdentityV1
from ibm_cloud_networking_services import DnsSvcsV1
from ibm_cloud_networking_services.dns_svcs_v1 import (
    ResourceRecordInputRdataRdataARecord,
    ResourceRecordInputRdataRdataPtrRecord,
)
from requests.exceptions import ReadTimeout
from retry import retry
import logging

logger = logging.getLogger(__name__)


def get_logger(mod_name):
    """
    To activate logs, setup the environment var LOGFILE
    e.g.: export LOGFILE=/tmp/ansible-ibmvpc.log
    Args:
        mod_name: module name
    Returns: Logger instance
    """

    logger = logging.getLogger(os.path.basename(mod_name))
    global LOGFILE
    LOGFILE = os.environ.get('LOGFILE')
    if not LOGFILE:
        logger.addHandler(logging.NullHandler())
    else:
        logging.basicConfig(level=logging.DEBUG, datefmt='%Y-%m-%d %H:%M:%S',
                            format='%(asctime)s %(levelname)s %(name)s %(message)s',
                            filename=LOGFILE, filemode='a')
    return logger

def get_resource_id(resource_name: str, response: Dict) -> str:
    """
    Retrieve the ID of the given resource from the provided response.

    Args:
        resource_name (str):    Name of the resource.
        response (Dict):        DetailedResponse returned from the collections.

    Returns:
        Resource id (str)

    Raises:
        ResourceNotFound    when there is a failure to retrieve the ID.
    """
    resource_id = get_resource_details(resource_name, response).get("id")

    if not resource_id:
        raise ResourceNotFound(f"Failed to retrieve the ID of {resource_name}.")


def get_resource_details(resource_name: str, response: Dict) -> Dict:
    """
    Returns the details for the provided resource_name from the given collection.

    Args:
        resource_name (str):    Name of the resource.
        response (Dict):        DetailedResponse returned from the collections.

    Returns:
        Resource details (dict)

    Raises:
        ResourceNotFound    when there is a failure to retrieve the ID.
    """
    resource_url = response["first"]["href"]
    resource_list_name = re.search(r"v1/(.*?)\?", resource_url).group(1)

    for i in response[resource_list_name]:
        if i["name"] == resource_name:
            return i
    return {}


class CephVMNodeIBMVPC:
    """
    A class to represent a Ceph VM Node in IBM Cloud VPC, responsible for
    retrieving volume information associated with a VPC instance.
    """
    
    def __init__(
        self,
        access_key: str,
        service_url: Optional[str] = "https://us-south.iaas.cloud.ibm.com/v1",
        dns_service_url: Optional[str] = "https://api.dns-svcs.cloud.ibm.com/v1",
        vsi_id: Optional[str] = None,
        node: Optional[Dict] = None
    ) -> None:
        """
        Initializes the CephVMNodeIBM instance with IBM Cloud API details.

        :param access_key: The API access key for IBM Cloud.
        :param service_url: The URL endpoint for IBM Cloud VPC service.
        :param dns_service_url: The URL endpoint for IBM Cloud dns service.
        :param vsi_id: The virtual server instance (VSI) ID.
        :param node: Node dictionary.
        """
        self._subnet: str = ""
        self._roles: list = list()
        self.node = None
        self._dns_service_instance_id = "b7efc2ce-ebf7-4dca-b7cf-b328171229a5"

        authenticator = IAMAuthenticator(access_key)
        self.vpc_service = VpcV1(authenticator=authenticator)
        if service_url:
            self.vpc_service.set_service_url(service_url=service_url)
        self.dnssvc = DnsSvcsV1(authenticator=authenticator)
        if dns_service_url:
            self.dnssvc.set_service_url(service_url=dns_service_url)

        if vsi_id:
            self.node = self.vpc_service.get_instance(id=vsi_id).get_result()

        if node:
            self.node = node

    def get_resource_groups(self, resource_group_name=None) -> None:
        """
        Retrieve resource groups information in the region.

        Args:
          resource_group_name: Name of resource group

        :return: Dictionary of resource group name and its ID.
        """
        vpcs_response = self.vpc_service.list_vpcs().get_result().get("vpcs", [])
        resource_groups_info = {}
        for each_vpc in vpcs_response:
            resource_groups_info.update({
                each_vpc["resource_group"]["name"]: each_vpc["resource_group"]["id"]
            })
        if resource_group_name:
            return resource_groups_info.get(resource_group_name)
        else:
            return resource_groups_info

    def get_vpcs(self, resource_group_name=None, resource_group_id=None, vpc_name=None) -> None:
        """
        Retrieve VPCs information in the region.

        Args:
          resource_group_name: Name of resource group to fetch the vpcs associated with it within the region
          resource_group_id: ID of resource group to fetch the vpcs associated with it within the region
          vpc_name: Name of VPC

        :return: List of VPCs, each as a dictionary.
        """
        try:
            if resource_group_name and not resource_group_id:
                resource_group_id = self.get_resource_groups(resource_group_name)

            response = self.vpc_service.list_vpcs(resource_group_id=resource_group_id).get_result()
            if vpc_name:
                vpc_response = get_resource_details(vpc_name, response)
                vpc_info = {
                    key: vpc_response[key] for key in ["name", "id", "classic_access", "cse_source_ips", "dns"]
                }
                for attribute in ["default_network_acl", "default_routing_table", "default_security_group", "resource_group"]:
                    vpc_info.update({
                        attribute: {key: vpc_response[attribute][key] for key in ["name", "id"]}
                    })
                return vpc_info
            else:
                vpcs_info = []
                vpcs = response.get("vpcs", [])

                for vpc_item in vpcs:
                    vpc_info = {
                        key: vpc_item[key] for key in ["name", "id", "classic_access", "cse_source_ips", "dns"]
                    }
                    for attribute in ["default_network_acl", "default_routing_table", "default_security_group", "resource_group"]:
                        vpc_info.update({
                            attribute: {key: vpc_item[attribute][key] for key in ["name", "id"]}
                        })
                    vpcs_info.append(vpc_info)
                return vpcs_info
        except Exception as e:
            raise Exception(f"Failed to retrieve VPCs: {e}")

    def get_subnets(self, resource_group_name=None, resource_group_id=None, zone_name=None, vpc_name=None, cidr=None) -> None:
        """
        Retrieve all subnets information in the region.

        Args:
          resource_group_name: Name of resource group to fetch the subnets associated with it within the region
          resource_group_id: ID of resource group to fetch the subnets associated with it within the region
          zone_name: Name of the zone to filter the subnets associated with it
          vpc_name: Name of VPC
          cidr: Filter subnet info based on cidr

        :return: List of subnets, each as a dictionary.
        """
        try:
            if resource_group_name and not resource_group_id:
                resource_group_id = self.get_resource_groups(resource_group_name)

            response = self.vpc_service.list_subnets(resource_group_id=resource_group_id, zone_name=zone_name, vpc_name=vpc_name).get_result()
            subnets = response.get("subnets", [])
            subnets_info = []
            for subnet_item in subnets:
                subnet_info = {
                    key: subnet_item[key] for key in ["name", "id", "ipv4_cidr_block", "available_ipv4_address_count"]
                }
                if cidr:
                    if subnet_info["ipv4_cidr_block"] == cidr:
                        subnets_info.append(subnet_info)
                else:
                    subnets_info.append(subnet_info)
            return subnets_info
        except Exception as e:
            raise Exception(f"Failed to retrieve subnets: {e}")

    def get_images(self, resource_group_name=None, resource_group_id=None, image_name=None) -> None:
        """
        Retrieve the images information.

        Args:
          resource_group_name: Name of resource group to fetch the images within the region
          resource_group_id: ID of resource group to fetch the images within the region
          image_name: Name of the image

        :return: Dictionary of images.
        """
        try:
            if resource_group_name and not resource_group_id:
                resource_group_id = self.get_resource_groups(resource_group_name)

            images = self.vpc_service.list_images(resource_group_id=resource_group_id, name=image_name).get_result().get("images", [])
            images_info = {image["name"]: image["id"] for image in images}
            if image_name:
                return images_info.get(image_name)
            return images_info
        except Exception as e:
            raise Exception(f"Failed to retrieve images: {e}")

    def get_sshkeys(self, resource_group_name=None, resource_group_id=None, key_name=None) -> None:
        """
        Retrieve the ssh keys information.

        Args:
          resource_group_name: Name of resource group to fetch the ssh keys associated with it
          resource_group_id: ID of resource group to fetch the ssh keys associated with it
          key_name: Name of the ssh key to filter the ssh keys

        :return: List of ssh keys, each as a dictionary.
        """
        try:
            if resource_group_name and not resource_group_id:
                resource_group_id = self.get_resource_groups(resource_group_name)

            ssh_keys = self.vpc_service.list_keys().get_result().get("keys", [])
            if resource_group_id:
                ssh_keys = [item for item in ssh_keys if item["resource_group"]["id"] == resource_group_id]
            sshkeys_info = []
            for sshkey_item in ssh_keys:
                sshkey_info = {
                    key: sshkey_item[key] for key in ["name", "id", "fingerprint", "public_key"]
                }
                sshkeys_info.append(sshkey_info)
            if key_name:
                return next((item for item in sshkeys_info if item["name"] == key_name), {})
            return sshkeys_info
        except Exception as e:
            raise Exception(f"Failed to retrieve ssh keys: {e}")

    def get_instance_profiles(self) -> List:
        """
        Retrieve the instance profiles information.

        Args:
          profile_name: Name of the instance profile

        :return: List of instance profiles.
        """
        try:
            profiles = self.vpc_service.list_instance_profiles().get_result().get("profiles", [])
            return [profile["name"] for profile in profiles]
        except Exception as e:
            raise Exception(f"Failed to retrieve instance profiles: {e}")

    def get_security_groups(self, resource_group_name=None, resource_group_id=None, vpc_name=None, group_name=None) -> None:
        """
        Retrieve the security groups information.

        Args:
          resource_group_name: Name of resource group to fetch the security groups associated with it within the region
          resource_group_id: ID of resource group to fetch the security groups associated with it within the region
          vpc_name: Name of VPC
          group_name: Name of the security group

        :return: Dictionary of security groups.
        """
        try:
            if resource_group_name and not resource_group_id:
                resource_group_id = self.get_resource_groups(resource_group_name)

            groups = self.vpc_service.list_security_groups(resource_group_id=resource_group_id, vpc_name=vpc_name).get_result().get("security_groups", [])
            groups_info = {item["name"]: item["id"] for item in groups}
            if group_name:
                return groups_info.get(group_name)
            return groups_info
        except Exception as e:
            raise Exception(f"Failed to retrieve security groups: {e}")

    def get_server_instances(self, resource_group_name=None, resource_group_id=None, vpc_name=None, instance_name=None) -> None:
        """
        Retrieve the virtual server instances information.

        Args:
          resource_group_name: Name of resource group to fetch the server instances associated with it within the region
          resource_group_id: ID of resource group to fetch the server instances associated with it within the region
          vpc_name: Name of VPC
          instance_name: Name of the server instance

        :return: List of dictionary of server instances
        """
        try:
            if resource_group_name and not resource_group_id:
                resource_group_id = self.get_resource_groups(resource_group_name)

            instances = self.vpc_service.list_instances(resource_group_id=resource_group_id, vpc_name=vpc_name, name=instance_name).get_result().get("instances", [])
            instances_info = []
            for vsi in instances:
                instance_info = {
                    "name": vsi["name"],
                    "id": vsi["id"],
                    "ip_address": vsi["primary_network_interface"]["primary_ip"]["address"],
                    "profile": vsi["profile"]["name"],
                    "zone": vsi["zone"]["name"],
                    "volumes": self.get_instance_volumes(vsi["id"])
                }
                for attribute in ["image", "primary_network_interface", "resource_group", "vpc"]:
                    instance_info[attribute] = vsi[attribute]["name"]

                instances_info.append(instance_info)
            if instance_name and len(instances_info) == 1:
                return instances_info[0]
            return instances_info
        except Exception as e:
            raise Exception(f"Failed to retrieve server instances: {e}")

    def get_instance_volumes(self, vsi_id) -> list:
        """
        Retrieve volume information associated with the instance.

        Args:
          vsi_id: ID of VSI instance

        :return: List of attached volumes, each as a dictionary.
        """
        try:
            volumes_info = []
            response = self.vpc_service.list_instance_volume_attachments(vsi_id)
            volume_attachments = response.get_result().get("volume_attachments", [])

            for attachment in volume_attachments:
                volume_info = {
                    "name": attachment["volume"]["name"],
                    "id": attachment["volume"]["id"],
                    "type": attachment["type"],
                    "delete_with_instance": attachment["delete_volume_on_instance_delete"]
                }
                volumes_info.append(volume_info)

            return volumes_info
        except ApiException as e:
            raise ApiException(f"Failed to retrieve volumes: {e}")

    def get_volumes(self, volume_name=None, zone_name=None, state=None) -> None:
        """
        Retrieve the volumes information.

        Args:
          volume_name: Name of the volume
          zone_name: Filter the volumes associated with the zone
          state: Filter volumes by attachment state

        :return: List of dictionary of volumes
        """
        try:
            volumes = self.vpc_service.list_volumes(name=volume_name, zone_name=zone_name, attachment_state=state).get_result().get("volumes", [])
            volumes_info = []
            for vol in volumes:
                vol_info = {
                    key: vol[key] for key in ["name", "id", "status", "active", "capacity", "attachment_state"]
                }
                vol_info["zone"] = vol["zone"]["name"]
                volumes_info.append(vol_info)
            if volume_name and len(volumes_info) == 1:
                return volumes_info[0]
            return volumes_info
        except Exception as e:
            raise Exception(f"Failed to retrieve volumes: {e}")

    def get_dnszones(self, instance_id=None, zone_name=None) -> None:
        """
        Retrieve the dns zones information.

        Args:
          instance_id: ID of dns service instance
          zone_name: Name of the dns zone

        :return: Dictionary of dns zones.
        """
        try:
            if not instance_id:
                instance_id = self._dns_service_instance_id
            zones = self.dnssvc.list_dnszones(instance_id=instance_id).get_result().get("dnszones", [])
            zones_info = {item["name"]: item["id"] for item in zones}
            if zone_name:
                return zones_info.get(zone_name)
            return zones_info
        except Exception as e:
            raise Exception(f"Failed to retrieve dns zones: {e}")

    def get_resource_records(self, zone_name=None, instance_id=None, record_name=None) -> None:
        """
        Retrieve the resource records information.

        Args:
          zone_name: Name of the dns zone
          instance_id: ID of dns service instance
          record_name: Name of the resource record

        :return: List of dictionary of resource records.
        """
        try:
            if not instance_id:
                instance_id = self._dns_service_instance_id
            zone_id = self.get_dnszones(instance_id=instance_id, zone_name=zone_name)
            resource_records = self.dnssvc.list_resource_records(instance_id=instance_id, dnszone_id=zone_id).get_result().get("resource_records", [])
            records_info = {item["name"]: item["id"] for item in resource_records}
            if record_name:
                return records_info.get(record_name)
            return resource_records
        except Exception as e:
            raise Exception(f"Failed to retrieve resource records: {e}")

    @property
    def floating_ips(self) -> List[str]:
        """Return the list of floating IP's"""
        if not self.node:
            return []

        resp = self.vpc_service.list_instance_network_interface_floating_ips(
            instance_id=self.node["id"],
            network_interface_id=self.node["primary_network_interface"]["id"],
        )

        return [
            x["address"] for x in resp.get("floating_ips") if x["status"] == "available"
        ]

    @property
    def public_ip_address(self) -> str:
        """Return the public IP address of the node."""
        if not self.node:
            return None

        resp = self.vpc_service.list_instance_network_interface_floating_ips(
            instance_id=self.node["id"],
            network_interface_id=self.node["primary_network_interface"]["id"],
        )

        floating_ips = []
        for float_ip in resp.get("floating_ips"):
            if (float_ip.get("status") == "available" and float_ip.get("type") == "public"):
                floating_ips.append(float_ip.get("address"))
        return floating_ips[0]

    @property
    def hostname(self) -> str:
        """Return the hostname of the VM."""
        end_time = datetime.now() + timedelta(seconds=30)
        while end_time > datetime.now():
            try:
                name, _, _ = socket.gethostbyaddr(self.ip_address)

                if name is not None:
                    return name
            except socket.herror:
                break

            sleep(5)

        return self.node["name"]

    @property
    def node_type(self) -> str:
        """Return the provider type."""
        return "ibmc"

    def create(
        self,
        node_name: str,
        image_name: str,
        network_name: str,
        private_key: str,
        vpc_name: str,
        profile: str,
        group_access: str,
        zone_name: str,
        zone_id_model_name: str,
        size_of_disks: int = 0,
        no_of_volumes: int = 0,
        userdata: str = "",
    ) -> None:
        """
        Create the instance in IBM Cloud with the provided data.

        Args:
            node_name           Name of the VM.
            image_name          Name of the image to use for creating the VM.
            network_name        Name of the Network
            private_key         Private ssh key
            access_key          Users IBM cloud access key
            vpc_name            Name of VPC
            profile             Node profile. EX: "bx2-2x8"
            group_access        group security policy
            zone_name           Name of zone
            zone_id_model_name  Name of zone identity model
            size_of_disks       size of disk
            no_of_volumes       Number of volumes for each node
            userdata            user related data

        """
        logger.info(f"Starting to create VM with name {node_name}")
        try:
            # Construct a dict representation of a VPCIdentityById model
            vpcs = self.service.list_vpcs()
            vpc_id = get_resource_id(vpc_name, vpcs.get_result())
            vpc_identity_model = dict({"id": vpc_id})

            subnets = self.service.list_subnets()
            subnet = get_resource_details(network_name, subnets.get_result())
            subnet_identity_model = dict({"id": subnet["id"]})
            self._subnet = subnet["ipv4_cidr_block"]

            security_group = self.service.list_security_groups()
            security_group_id = get_resource_id(
                group_access, security_group.get_result()
            )
            security_group_identity_model = dict({"id": security_group_id})

            # Construct a dict representation of a NetworkInterfacePrototype model
            network_interface_prototype_model = dict(
                {
                    "allow_ip_spoofing": False,
                    "subnet": subnet_identity_model,
                    "security_groups": [security_group_identity_model],
                }
            )

            # Construct a dict representation of a ImageIdentityById model
            images = self.service.list_images(name=image_name)
            image_id = get_resource_id(image_name, images.get_result())
            image_identity_model = dict({"id": image_id})

            # Construct a dict representation of a KeyIdentityById model
            keys = self.service.list_keys()
            key_id = get_resource_id(private_key, keys.get_result())

            key_identity_model = dict({"id": key_id})
            key_identity_shared = {
                "fingerprint": "SHA256:PDSaOCv0NXGlpV5IYVzxNUK/8bHCG7ywlkkNI/RITIk"
            }

            # Construct a dict representation of a ResourceIdentityById model
            resource_group_identity_model = dict(
                {"id": "1355ac9cc947499bbb1a9029b7982299"}
            )

            # Construct a dict representation of a InstanceProfileIdentityByName model
            instance_profile_identity_model = dict({"name": profile})

            # Construct a dict representation of a ZoneIdentityByName model
            zone_identity_model = dict({"name": zone_id_model_name})

            # Construct a dict representation of a VolumeProfileIdentityByName model
            volume_profile_identity_model = dict({"name": "general-purpose"})

            volume_attachment_list = []
            for i in range(0, no_of_volumes):
                volume_attachment_volume_prototype_instance_context_model1 = dict(
                    {
                        "name": f"{node_name.lower()}-{str(i)}",
                        "profile": volume_profile_identity_model,
                        "capacity": size_of_disks,
                    }
                )

                volume_attachment_prototype_instance_context_model1 = dict(
                    {
                        "delete_volume_on_instance_delete": True,
                        "volume": volume_attachment_volume_prototype_instance_context_model1,
                    }
                )

                volume_attachment_list.append(
                    volume_attachment_prototype_instance_context_model1
                )

            # Prepare the VSI payload
            instance_prototype_model = dict(
                {"keys": [key_identity_model, key_identity_shared]}
            )

            instance_prototype_model["name"] = node_name.lower()
            instance_prototype_model["profile"] = instance_profile_identity_model
            instance_prototype_model["resource_group"] = resource_group_identity_model
            instance_prototype_model["user_data"] = userdata
            instance_prototype_model["volume_attachments"] = volume_attachment_list
            instance_prototype_model["vpc"] = vpc_identity_model
            instance_prototype_model["image"] = image_identity_model
            instance_prototype_model["primary_network_interface"] = (
                network_interface_prototype_model
            )
            instance_prototype_model["zone"] = zone_identity_model

            # Set up parameter values
            instance_prototype = instance_prototype_model
            response = self.service.create_instance(instance_prototype)

            instance_id = response.get_result()["id"]
            self.wait_until_vm_state_running(instance_id)

            response = self.service.get_instance(instance_id)
            self.node = response.get_result()

            # DNS record creation phase
            logger.debug(f"Adding DNS records for {node_name}")
            dns_zone = self.dns_service.list_dnszones(
                "b7efc2ce-ebf7-4dca-b7cf-b328171229a5"
            )
            dns_zone_id = get_dns_zone_id(zone_name, dns_zone.get_result())

            resource = self.dns_service.list_resource_records(
                instance_id="b7efc2ce-ebf7-4dca-b7cf-b328171229a5",
                dnszone_id=dns_zone_id,
            )
            records_a = [
                i for i in resource.get_result()["resource_records"] if i["type"] == "A"
            ]
            records_ip = [
                i
                for i in records_a
                if i["rdata"]["ip"]
                == self.node["primary_network_interface"]["primary_ipv4_address"]
            ]
            if records_ip:
                self.dns_service.update_resource_record(
                    instance_id="b7efc2ce-ebf7-4dca-b7cf-b328171229a5",
                    dnszone_id=dns_zone_id,
                    record_id=records_ip[0]["id"],
                    name=self.node["name"],
                    rdata=records_ip[0]["rdata"],
                )

            a_record = ResourceRecordInputRdataRdataARecord(
                self.node["primary_network_interface"]["primary_ipv4_address"]
            )
            self.dns_service.create_resource_record(
                instance_id="b7efc2ce-ebf7-4dca-b7cf-b328171229a5",
                dnszone_id=dns_zone_id,
                type="A",
                ttl=900,
                name=self.node["name"],
                rdata=a_record,
            )

            ptr_record = ResourceRecordInputRdataRdataPtrRecord(
                f"{self.node['name']}.{zone_name}"
            )
            self.dns_service.create_resource_record(
                instance_id="b7efc2ce-ebf7-4dca-b7cf-b328171229a5",
                dnszone_id=dns_zone_id,
                type="PTR",
                ttl=900,
                name=self.node["primary_network_interface"]["primary_ipv4_address"],
                rdata=ptr_record,
            )

        except NodeError:
            raise
        except BaseException as be:  # noqa
            logger.error(be)
            raise NodeError(f"Unknown error. Failed to create VM with name {node_name}")

    def delete(self, zone_name: Optional[str] = None) -> None:
        """
        Removes the VSI instance from the platform along with its DNS record.

        Args:
            zone_name (str):    DNS Zone name associated with the instance.
        """
        if not self.node:
            return

        node_id = self.node["id"]
        node_name = self.node["name"]

        try:
            self.remove_dns_records(zone_name)
        except BaseException:  # noqa
            logger.warning(f"Encountered an error in removing DNS records of {node_name}")
            pass

        logger.info(f"Preparing to remove {node_name}")
        resp = self.service.delete_instance(node_id)

        if resp.get_status_code() != 204:
            logger.debug(f"{node_name} cannot be found.")
            return

        # Wait for the VM to be delete
        end_time = datetime.now() + timedelta(seconds=600)
        while end_time > datetime.now():
            sleep(5)
            try:
                resp = self.service.get_instance(node_id)
                if resp.get_status_code == 404:
                    logger.info(f"Successfully removed {node_name}")
                    return
            except ApiException:
                logger.info(f"Successfully removed {node_name}")
                self.remove_dns_records(zone_name)
                return

        logger.debug(resp.get_result())
        raise NodeDeleteFailure(f"Failed to remove {node_name}")

    def wait_until_vm_state_running(self, instance_id: str) -> None:
        """
        Waits until the VSI moves to a running state within the specified time.

        Args:
            instance_id (str)   The ID of the VSI to be checked.

        Returns:
            None

        Raises:
            NodeError
        """
        start_time = datetime.now()
        end_time = start_time + timedelta(seconds=1200)

        node_details = None
        while end_time > datetime.now():
            sleep(5)
            resp = self.service.get_instance(instance_id)
            if resp.get_status_code() != 200:
                logger.debug("Encountered an error getting the instance.")
                sleep(5)
                continue

            node_details = resp.get_result()
            if node_details["status"] == "running":
                end_time = datetime.now()
                duration = (end_time - start_time).total_seconds()
                logger.info(
                    "%s moved to running state in %d seconds.",
                    node_details["name"],
                    int(duration),
                )
                return

            if node_details["status"] == "failed":
                raise NodeError(node_details["status_reasons"])

        raise NodeError(f"{node_details['name']} is in {node_details['status']} state.")

    @retry(ConnectionError, tries=3, delay=60)
    def remove_dns_records(self, zone_name):
        """
        Remove the DNS records associated this VSI.

        Args:
            zone_name (str):    DNS zone name associated with this VSI
        """
        if not self.node:
            return

        zones = self.dns_service.list_dnszones("b7efc2ce-ebf7-4dca-b7cf-b328171229a5")
        zone_id = get_dns_zone_id(zone_name, zones.get_result())
        zone_instance_id = get_dns_zone_instance_id(zone_name, zones.get_result())

        resp = self.dns_service.list_resource_records(
            instance_id=zone_instance_id, dnszone_id=zone_id
        )
        records = resp.get_result()

        # ToDo: There is a maximum of 200 records that can be retrieved at a time.
        #       Support pagination is required.
        for record in records["resource_records"]:
            if record["type"] == "A" and self.node.get("name") in record["name"]:
                if record.get("linked_ptr_record"):
                    logger.info(
                        f"Deleting PTR record {record['linked_ptr_record']['name']}"
                    )
                    self.dns_service.delete_resource_record(
                        instance_id="b7efc2ce-ebf7-4dca-b7cf-b328171229a5",
                        dnszone_id=zone_id,
                        record_id=record["linked_ptr_record"]["id"],
                    )

                logger.info(f"Deleting Address record {record['name']}")
                self.dns_service.delete_resource_record(
                    instance_id="b7efc2ce-ebf7-4dca-b7cf-b328171229a5",
                    dnszone_id=zone_id,
                    record_id=record["id"],
                )

                return

        # This code path can happen if there are no matching/associated DNS records
        # Or we have a problem
        logger.debug(f"No matching DNS records found for {self.node['name']}")


class ResourceNotFound(Exception):
    pass


class NodeError(Exception):
    pass


class NodeDeleteFailure(Exception):
    pass
