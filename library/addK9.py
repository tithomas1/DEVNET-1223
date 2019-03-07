#!/usr/bin/env python

# Author:  Joel Roberts (joerober@cisco.com) 
# Created: 7/7/17
# Version: 1.0  (no error checking, hard-coded tftp server + image)
#
# Ansible module that uses telnet connection
# to install k9-sec.pie to a Cisco IOS XR device
#       *this requires or assumes tftp server with appropriate k9-sec image 
#	
#	Initial version calls conTelnet.py module and class 
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
module: addK9
author: "Joel Roberts (joerober@cisco.com)"
short_description: Install add k9-sec.pie to IOS XR via telnet
description:
  - Simple module to install add k9sec in order to enable ssh 
    to an IOS XR target. Essentially "bootstrap" router for ssh.
options:
"""

EXAMPLES = """
  vars_files:
    - secrets.yaml

  tasks:
    - name: Install add activate k9sec 
      addK9:
        provider: "{{ credentials }}"                   
      register: result
    - debug: var=result
"""

from ansible.module_utils.basic import *
import sys                                          
sys.path.append('/app/library/')        
import conTelnet 


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

    # use conTelnet.py to connect and install k9sec, create keys, config ssh
    # conTelnet.py uses tftp to copy image; version 1.0 server + file set in conTelnet.py

    connection = conTelnet.conTelnet(targetHost,username,password) 
    connection.connectHost() 
    connection.addSecPie() 
    connection.addCryptoSsh() 
    connection.close()

    #  No error checking (version 1.0)...assume changes made

    customModule.exit_json(changed=True)


if __name__ == '__main__':
    main()
