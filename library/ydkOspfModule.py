#!/usr/bin/python

# Author:  Tim Thomas (tithomas@cisco.com)
# Created: 3/8/17
#
# Simple example of a custom Ansible module that uses YDK to create/update
# basic OSPF configuration on a target IOS-XR device
#
# Note the module tries to be idempotent...

# TODO: Finish areas section in DOCUMENTATION string

DOCUMENTATION = """
---
module: ydkOspfModule
author: "Tim Thomas (tithomas@cisco.com)"
short_description: Manage IOS-XR OSPF configuration using Cisco's YANG Development Kit (YDK)
description:
  - A simple example of a custom Ansible module for managing Cisco IOS-XR OSPF configuration
    using a YANG-based auto-generated API. Only some basic OSPF parameters are supported.
options:
  provider:
    description:
      - Connection info for target. Must specify 'host', 'username', and 'password'. 'port'
        optional (default 830)
    required: true
  process:
    description:
      - OSPF process name
    required: true
  state:
    description:
      - Whether the OSPF process should be configured or not
    required: false
    choices: ['present', 'absent']
    default: present
  router-id:
    description:
      - Router-id associated with the process
    required: false
    default: 1.1.1.1
  areas:
    description:
      - Configuration for one or more OSPF areas. Note this is a nested dictionary that
        describes each area's target configuration state
    required: false
    default: null
"""

EXAMPLES = """
# Note: The examples below use the following provider dictionary to specify the target
#       device and its authentication.
vars:
  ydk:
    host: "{{ inventory_hostname }}"
    username: cisco
    password: cisco
- name: OSPF process 2
    ydkOspfModule:
      process: 2
      state: present
      router-id: 1.1.1.1
      areas:
        0:
          interfaces:
            Loopback2:
              passive: True
        1:
          interfaces:
            GigabitEthernet1/0/0/0
              type: point-to-point
            GigabitEthernet1/0/1/0
              type: point-to-point
      provider: "{{ ydk }}"
"""

from ansible.module_utils.basic import *
from collections import namedtuple
import logging

try:
    from ydk.errors import YPYError
    from ydk.types import Empty
    from ydk.providers import NetconfServiceProvider
    from ydk.services import CRUDService
    from ydk.models.ciscolive_ansible_ospf import Cisco_IOS_XR_ipv4_ospf_cfg
    from ydk.models.ciscolive_ansible_ospf import openconfig_interfaces
    YDK_AVAILABLE = True
except ImportError:
    YDK_AVAILABLE = False

ANSIBLE_METADATA = {'status': ['preview'], 'supported_by': 'community', 'version': '0.1'}

NETCONF_PORT = 830

moduleArguments = {
    'provider': {'required': True, 'type': 'dict'},
    'process': {'required': True, 'type': 'str'},
    'state': {'default': 'present', 'choices': ['present', 'absent'], 'type': 'str'},
    'router-id': {'default': '1.1.1.1', 'type': 'str'},
    'areas': {'type': 'dict'}
}


# List of valid interface names extracted from the target device

validInterfaceNameList = []

YDKTargetParamError = namedtuple('YDKTargetParamError', ['errFlag', 'errMsg'])


class YDKTarget:
    def __init__(self, host=None, username=None, password=None, port=NETCONF_PORT):
        self._address = host
        self._port = port
        self._username = username
        self._password = password
        self._provider = None
        self._crudService = CRUDService()

    # Just in case an error occurs somewhere in the YDK API. It will mess with
    # Ansible, but at least there's a chance of seeing what happened

    @staticmethod
    def _setupLogging():
        logger = logging.getLogger('ydk')
        # logger.setLevel(logging.DEBUG)
        logger.setLevel(logging.ERROR)
        handler = logging.StreamHandler()
        formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    def checkParams(self):
        if self._address is None:
            return YDKTargetParamError(True, 'missing host parameter')
        if self._username is None:
            return YDKTargetParamError(True, 'missing username parameter')
        if self._password is None:
            return YDKTargetParamError(True, 'missing password parameter')
        return YDKTargetParamError(False, 'ok')

    def info(self):
        return [self._address, self._port, self._username, self._password]

    def connect(self):
        self._setupLogging()
        self._provider = NetconfServiceProvider(address=self._address, port=self._port,
                                                username=self._username, password=self._password)

    def close(self):
        self._provider.close()

    def create(self, config):
        return self._crudService.create(self._provider, config)

    def read(self, filterSpec):
        return self._crudService.read(self._provider, filterSpec)

    def update(self, config):
        return self._crudService.update(self._provider, config)

    def delete(self, config):
        return self._crudService.delete(self._provider, config)

    def getCapabilities(self):
        return self._provider._get_capabilities()

    def validateModelCapability(self, modelName):
        pattern = re.compile(modelName + '\?')
        capabilities = self._provider._get_capabilities()
        for capability in capabilities:
            if pattern.match(capability):
                return True
        return False


# Define a custom exception class in case there's a problem encountered
# deep in one of the following routines and we need to bail out. The
# exception should be dealt with before transferring control back to
# Ansible

class YdkModuleException(Exception):
    def __init__(self, yErrorMetaInfo):
        Exception.__init__(self)
        self.yErrorMetaInfo = yErrorMetaInfo

    def __str__(self):
        return json.dumps(self.yErrorMetaInfo)


# Utility routine to find enums by their name. Useful for checking params
# from the playbook against enums defined in the YDK model(s) without
# knowing what those keywords might be ahead of time

def getEnumByKeyword(enum, keyword):
    for name, v in enum.__dict__['_member_map_'].items():
        if name == keyword:
            return enum(v.value)
    return None


# The code has assert isinstance() calls scattered around to provide hints to
# the IDE as to the types of some variables, especially those that YDK defines
# as generic YList elements. It really doesn't do anything other than help with
# typing completion

def findOspfProcessByName(ospfState, processName):
    assert isinstance(ospfState, Cisco_IOS_XR_ipv4_ospf_cfg.Ospf)
    for process in ospfState.processes.process:
        assert isinstance(process, Cisco_IOS_XR_ipv4_ospf_cfg.Ospf.Processes.Process)
        if process.process_name == processName:
            return process
    return None


def findOspfAreaById(ospfProcessState, areaId):
    assert isinstance(ospfProcessState, Cisco_IOS_XR_ipv4_ospf_cfg.Ospf.Processes.Process)
    for areaAreaId in ospfProcessState.default_vrf.area_addresses.area_area_id:
        assert isinstance(areaAreaId, Cisco_IOS_XR_ipv4_ospf_cfg.Ospf.Processes.Process.DefaultVrf.AreaAddresses.AreaAreaId)
        if areaAreaId.area_id == areaId:
            return areaAreaId
    return None


# Validate that the interface name actually exists on the target device

def findAreaInterfaceByName(existingArea, interface):
    assert isinstance(existingArea, Cisco_IOS_XR_ipv4_ospf_cfg.Ospf.Processes.Process.DefaultVrf.AreaAddresses.AreaAreaId)
    for existingInterface in existingArea.name_scopes.name_scope:
        assert isinstance(existingInterface, Cisco_IOS_XR_ipv4_ospf_cfg.Ospf.Processes.Process.DefaultVrf.AreaAddresses.AreaAreaId.NameScopes.NameScope)
        if existingInterface.interface_name == interface:
            return existingInterface
    return None


def updateNameScope(nameScope, name, params):
    assert isinstance(nameScope, Cisco_IOS_XR_ipv4_ospf_cfg.Ospf.Processes.Process.DefaultVrf.AreaAddresses.AreaAreaId.NameScopes.NameScope)
    hasChanged = False

    if 'passive' in params:
        if nameScope.passive != params['passive']:
            nameScope.passive = params['passive']
            hasChanged = True

    # TODO: Should Loopback interfaces be passive regardless?
    pattern = re.compile('loopback[1-9][0-9]*')
    assert isinstance(name, str)
    if pattern.match(name.lower()):
        if nameScope.passive is None:
            hasChanged = True
        nameScope.passive = True

    # The network type keyword translates to an enum class in the model

    if 'type' in params:
        typeKeyword = params['type'].lower().replace('-', '_')
        networkType = getEnumByKeyword(Cisco_IOS_XR_ipv4_ospf_cfg.OspfNetworkEnum, typeKeyword)
        if networkType is None:
            raise YdkModuleException({'level': 'modifyNameScope', 'error': 'unknown network type', 'type': params['type']})
        if nameScope.network_type != networkType:
            nameScope.network_type = networkType
            hasChanged = True
    return hasChanged


def createNameScope(name, params):
    # TODO: Maybe move check for valid interface name to here
    nameScope = Cisco_IOS_XR_ipv4_ospf_cfg.Ospf.Processes.Process.DefaultVrf.AreaAddresses.AreaAreaId.NameScopes.NameScope()
    nameScope.interface_name = name
    updateNameScope(nameScope, name, params)
    nameScope.running = Empty()
    return nameScope


# Create a new OSPF area

def createOspfArea(areaId, areaParams):
    areaAreaId = Cisco_IOS_XR_ipv4_ospf_cfg.Ospf.Processes.Process.DefaultVrf.AreaAddresses.AreaAreaId()
    areaAreaId.area_id = int(areaId)
    if 'interfaces' in areaParams:
        for interface, interfaceParams in areaParams['interfaces'].items():
            if interface not in validInterfaceNameList:
                raise YdkModuleException({'level': 'createOspfArea', 'error': 'interface name not on target', 'name': interface})
            areaAreaId.name_scopes.name_scope.append(createNameScope(interface, interfaceParams))
    areaAreaId.running = Empty()
    return areaAreaId


# Update the attributes of an existing area

def updateOspfArea(existingArea, areaParams):
    hasChanged = False
    if 'interfaces' in areaParams:
        for interface, interfaceParams in areaParams['interfaces'].items():
            existingInterface = findAreaInterfaceByName(existingArea, interface)
            if existingInterface:
                if updateNameScope(existingInterface, interface, interfaceParams):
                    hasChanged = True
            else:
                if interface not in validInterfaceNameList:
                    raise YdkModuleException({'level': 'updateOspfArea', 'error': 'interface name not on target', 'name': interface})
                existingArea.name_scopes.name_scope.append(createNameScope(interface, interfaceParams))
                hasChanged = True
    return hasChanged


# Create a completely new OSPF process with provided area info

def createOspfProcess(params):
    # Need to construct the class hierarchy starting at the top. The API Ospf()
    # constructor creates an empty process list

    ospf = Cisco_IOS_XR_ipv4_ospf_cfg.Ospf()
    ospfProcess = Cisco_IOS_XR_ipv4_ospf_cfg.Ospf.Processes.Process()
    ospfProcess.process_name = params['process']
    ospfProcess.default_vrf.router_id = params['router-id']
    ospfProcess.start = Empty()

    # Construct any new area(s)

    if 'areas' in params:
        for area, areaParams in params['areas'].items():
            if type(areaParams) is not dict:
                raise YdkModuleException({'level': 'createOspfProcess', 'error': 'Area parameters not dictionary'})
            else:
                ospfProcess.default_vrf.area_addresses.area_area_id.append(createOspfArea(area, areaParams))

    ospf.processes.process.append(ospfProcess)
    return ospf


# Update the attributes of an existing OSPF process

def updateOspfProcess(existingOspfProcess, params):
    hasChanged = False
    if existingOspfProcess.default_vrf.router_id != params['router-id']:
        existingOspfProcess.default_vrf.router_id = params['router-id']
        hasChanged = True
    if 'areas' in params:
        for area, areaParams in params['areas'].items():
            if type(areaParams) is not dict:
                raise YdkModuleException({'level': 'modifyOspfProcess', 'error': 'Area parameters not dictionary'})
            existingArea = findOspfAreaById(existingOspfProcess, int(area))
            if existingArea is None:
                existingOspfProcess.default_vrf.area_addresses.area_area_id.append(createOspfArea(area, areaParams))
                hasChanged = True
            elif updateOspfArea(existingArea, areaParams):
                    hasChanged = True
    return hasChanged


# Build a list of all the existing interfaces on the target device

def extractInterfaceList(currentIntfConfig):
    global validInterfaceNameList
    for interface in currentIntfConfig.interface:
        validInterfaceNameList.append(interface.name)


# statePresent() and stateAbsent() are the two main driving functions

def statePresent(customModule):
    ydkTarget = YDKTarget(**customModule.params['provider'])
    paramChk = ydkTarget.checkParams()
    if paramChk.errFlag:
        customModule.fail_json(msg=paramChk.errMsg, meta={'present': 'checkParams'})
    ydkTarget.connect()

    # TODO: Assume should pull the current OSPF operational state
    currentOspfConfig = ydkTarget.read(Cisco_IOS_XR_ipv4_ospf_cfg.Ospf())
    currentIntfConfig = ydkTarget.read(openconfig_interfaces.Interfaces())
    extractInterfaceList(currentIntfConfig)

    existingOspfProcess = findOspfProcessByName(currentOspfConfig, customModule.params['process'])

    # If the process exists, then there might be modifications

    if existingOspfProcess:
        assert isinstance(existingOspfProcess, Cisco_IOS_XR_ipv4_ospf_cfg.Ospf.Processes.Process)
        try:
            hasChanged = updateOspfProcess(existingOspfProcess, customModule.params)
            if hasChanged and not customModule.check_mode:
                ydkTarget.update(currentOspfConfig)
        except YdkModuleException as e:
            ydkTarget.close()
            customModule.fail_json(msg='unable to update OSPF process', meta=e.yErrorMetaInfo)
        ydkTarget.close()
        return hasChanged, {'process': existingOspfProcess.process_name}

    # Otherwise the process doesn't exist, so create it

    try:
        newOspfProcess = createOspfProcess(customModule.params)
        if not customModule.check_mode:
            ydkTarget.create(newOspfProcess)
    except YdkModuleException as e:
        ydkTarget.close()
        customModule.fail_json(msg='unable to create OSPF process', meta=e.yErrorMetaInfo)
    ydkTarget.close()
    return True, {'process': customModule.params['process'], 'state': 'created'}


def stateAbsent(customModule):
    ydkTarget = YDKTarget(**customModule.params['provider'])
    paramChk = ydkTarget.checkParams()
    if paramChk.errFlag:
        customModule.fail_json(msg=paramChk.errMsg, meta={'absent': 'checkParams'})
    else:
        metaInfo = {'process': customModule.params['process']}
    ydkTarget.connect()
    currentOspfConfig = ydkTarget.read(Cisco_IOS_XR_ipv4_ospf_cfg.Ospf())
    ospfProcess = findOspfProcessByName(currentOspfConfig, customModule.params['process'])

    # If the target process exists, then just delete the whole thing for now
    # TODO: Maybe look at only deleting parts of an OSPF process, for example certain areas

    if ospfProcess:
        assert isinstance(ospfProcess, Cisco_IOS_XR_ipv4_ospf_cfg.Ospf.Processes.Process)
        if not customModule.check_mode:
            ydkTarget.delete(ospfProcess)
        ydkTarget.close()
        return True, {'process': customModule.params['process'], 'state': 'removed'}
    ydkTarget.close()
    return False, metaInfo


def main():
    moduleCallMap = {
        'present': statePresent,
        'absent':  stateAbsent
    }

    customModule = AnsibleModule(argument_spec=moduleArguments, supports_check_mode=True)

    if not YDK_AVAILABLE:
        customModule.fail_json(msg='unable to import one or more required YDK packages')

    try:
        hasChanged, result = moduleCallMap.get(customModule.params['state'])(customModule)
        customModule.exit_json(changed=hasChanged, meta=result)
    except YPYError as e:
        # Looks like some of the raise YPYError (and subclasses) in YDK pass a string as the
        # first positional, whereas the exception definitions define a code first then the
        # string. It ends up meaning the message might be in either the code or message field.
        errMsg = e.message if e.message else e.code
        customModule.fail_json(msg='YDK error occurred', meta={'YDKErrorMsg': errMsg})
    except Exception as e:
        import traceback
        customModule.fail_json(msg='caught general exception',
                               meta={'exceptionType': type(e).__name__,
                                     'exceptionInfo': traceback.format_exception(sys.exc_info()[0], sys.exc_info()[1], sys.exc_info()[2])})


if __name__ == '__main__':
    main()
