#!/usr/bin/env python

# Author:  Joel Roberts (joerober@cisco.com) 
# Created: 7/7/17
#
# Ansible module that moves VIRL XRVR Mgmt Interface into default vrf
#
# ------------------------------------------------------------------
# Copyright 2017 Cisco Systems
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ------------------------------------------------------------------

DOCUMENTATION = """
---
module: no-vrfmgmt 
author: "Joel Roberts (joerober@cisco.com)"
short_description: Put Mgmt Int into default
description:
  - Move XRVR (VIRL) Mgmt Interface from mgmt vrf to default vrf 
options:
"""

EXAMPLES = """
  vars_files:
    - secrets.yaml

  tasks:
    - name: place XR mgmt interface into default vrf
      no-vrfmgmt:
        provider: "{{ credentials }}"
      register: result
    - debug: var=result
"""

from ansible.module_utils.basic import *
import telnetlib
import sys
import socket

ANSIBLE_METADATA = {'status': ['preview'], 'supported_by': 'community', 'version': '0.1'}

moduleArguments = {
    'provider': {'required': True, 'type': 'dict'},
}


def main():
    customModule = AnsibleModule(argument_spec=moduleArguments, supports_check_mode=False)

    providerParams = customModule.params['provider']
    targetHost = providerParams['host']
    username = providerParams['username']
    password = providerParams['password']

    # get ip address of host (assumes proper name resolution configured) 
    ipaddr= socket.gethostbyname(targetHost)

    # connect to XR router & change interface Mgmt0/0/CPU0/0 to default vrf

    connection = telnetlib.Telnet(targetHost) 
    connection.read_until("Username:")
    connection.write(username + "\n") 
    connection.read_until("Password:") 
    connection.write(password + "\n") 
    connection.read_until(targetHost+"#")
    connection.write("configure terminal\n") 
    connection.read_until(targetHost+"(config)#")
    connection.write("interface MgmtEth 0/0/CPU0/0\n")
    connection.read_until(targetHost+"(config-if)#") 
    connection.write("no ipv4 address\n") 
    connection.read_until(targetHost+"(config-if)#") 
    connection.write("no vrf Mgmt-intf\n")
    connection.read_until(HOST+"(config-if)#")
    connection.write("ipv4 address " + ipaddr + " 255.255.255.0\n")
    connection.read_until(HOST+"(config-if)#")
    connection.write("commit\n")
    connection.write("\n\n") 
    connection.read_all()
    connection.close()
    
    # Just assume changes were made

    customModule.exit_json(changed=True)


if __name__ == '__main__':
    main()
