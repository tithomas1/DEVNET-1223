#!/usr/bin/python

# Author:  Tim Thomas (tithomas@cisco.com)
# Created: 4/25/17
#
# Simple example of a custom Ansible module that uses YDK to create/update
# MACsec keychain configuration on a target IOS-XR device
#
# Note the module tries to be idempotent...
#
# TODO: More detailed DOCUMENTATION string
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
module: ydkMACsecModule
author: "Tim Thomas (tithomas@cisco.com)"
short_description: Manage IOS-XR MACsec keychain using Cisco's YANG Development Kit (YDK)
description:
  - A simple example of a custom Ansible module for managing Cisco IOS-XR MACsec keychains
    using a YANG-based auto-generated API.
options:
  provider:
    description:
      - Connection info for target. Must specify 'host', 'username', and 'password'. 'port'
        optional (default 830)
    required: true
  keychain:
    description:
      - MACsec keychain name
    required: true
  keys:
    description:
      - List of keys, each with a name, key-string, algorithm, and lifetime
    required: false
  state:
    description:
      - Whether the MACsec keychain should be configured or not
    required: false
    choices: ['present', 'absent']
    default: present
"""

EXAMPLES = """
# Note: The examples below use the following provider dictionary to specify the target
#       device and its authentication
vars:
  ydk:
    host: "{{ inventory_hostname }}"
    username: cisco
    password: cisco
- name: MACsec keychain 1
    ydkMACsecModule:
      keychain: CHAIN1
      state: present
      keys:
        10:
          key-string: '12485546375E5450087E727C6061754654325623030D0F710357544F417A0E01050102015F0853510C03514353510B585629716A1E5A495042315E5C50097F7778'
          algorithm: aes-256-cmac
          lifetime:
            start-time: '00:00:00AM'
            start-date: 1-Jan-2017
        20:
          key-string: '11594D5544472859547F0A737D62137330524E5750030B0C020059563E437F0D01'
          algorithm: aes-128-cmac
          lifetime:
            start-time: '00:00:00'
            start-date: 1-May-2017
            end-time: '11:59:59p'
            end-date: 31-Dec-2017
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

    # I'm importing the MACsec keychain model from a smaller, generated API. Flip the
    # import if using the Cisco IOS-XR models that come with ydk-py

    from ydk.models.ciscolive_ansible_macsec import Cisco_IOS_XR_lib_keychain_macsec_cfg
    # from ydk.models.cisco_ios_xr import Cisco_IOS_XR_lib_keychain_macsec_cfg
    YDK_AVAILABLE = True
except ImportError:
    YDK_AVAILABLE = False


ANSIBLE_METADATA = {'status': ['preview'], 'supported_by': 'community', 'version': '0.1'}

NETCONF_PORT = 830

# Do these patterns need to be this specific? YDK will catch range errors
#
# The time can be 24-hour (military) or 12-hour optionally appended with am or pm

TIME_PATTERN = re.compile(r'^([0-1]?\d|2[0-3])(?::([0-5]?\d))?(?::([0-5]?\d))?\s?(?i)([ap](?:m?))?$')
DATE_PATTERN = re.compile(r'^([0-2]?\d|3[01])-([a-z]{3})-(20\d{2})$')

DEFAULT_CRYPTO = 'aes_256_cmac'

moduleArguments = {
    'provider': {'required': True, 'type': 'dict'},
    'keychain': {'required': True, 'type': 'str'},
    'state': {'default': 'present', 'choices': ['present', 'absent'], 'type': 'str'},
    'keys': {'type': 'dict'}
}


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

def findKeychainByName(keychainsConfig, keychainName):
    assert isinstance(keychainsConfig, Cisco_IOS_XR_lib_keychain_macsec_cfg.MacSecKeychains)
    for keychain in keychainsConfig.mac_sec_keychain:
        assert isinstance(keychain, Cisco_IOS_XR_lib_keychain_macsec_cfg.MacSecKeychains.MacSecKeychain)
        if keychain.chain_name == keychainName:
            return keychain
    return None


def findKeyById(keychainConfig, keyId):
    assert isinstance(keychainConfig, Cisco_IOS_XR_lib_keychain_macsec_cfg.MacSecKeychains.MacSecKeychain)
    for key in keychainConfig.keies.key:
        assert isinstance(key, Cisco_IOS_XR_lib_keychain_macsec_cfg.MacSecKeychains.MacSecKeychain.Keies.Key)
        if key.key_id == keyId:
            return key
    return None


def createKeyLifetime(lifetimeParams):
    newLifetime = Cisco_IOS_XR_lib_keychain_macsec_cfg.MacSecKeychains.MacSecKeychain.Keies.Key.Lifetime()

    # Set a reasonable default start time/date, i.e. 00:00:00 on 01-Jan-2017

    newLifetime.start_hour = 0
    newLifetime.start_minutes = 0
    newLifetime.start_seconds = 0
    newLifetime.start_date = 1
    newLifetime.start_month = getEnumByKeyword(Cisco_IOS_XR_lib_keychain_macsec_cfg.MacSecKeyChainMonthEnum, 'jan')
    newLifetime.start_year = 2017

    # Initially assume infinite lifetime unless some end time/date specified. If
    # an end time was given, assume today's date until maybe overridden. If an
    # end date was given but no end time, then assume the end of that day

    infiniteFlag = True
    if 'end-time' in lifetimeParams:
        infiniteFlag = False
        today = datetime.date.today()
        newLifetime.end_date = today.day
        newLifetime.end_month = today.month - 1
        newLifetime.end_year = today.year
    if 'end-date' in lifetimeParams:
        infiniteFlag = False
        if 'end-time' not in lifetimeParams:
            lifetimeParams['end-time'] = '23:59:59'

    # Should be enough setup to hand off to updateKeyLifetime() for the rest

    newLifetime.infinite_flag = infiniteFlag
    updateKeyLifetime(newLifetime, lifetimeParams)
    return newLifetime


# updateKeyLifetime() does the bulk of the work of setting/updating the start/end
# date/time on the key

def updateKeyLifetime(existingLifetime, lifetimeParams):
    assert isinstance(existingLifetime, Cisco_IOS_XR_lib_keychain_macsec_cfg.MacSecKeychains.MacSecKeychain.Keies.Key.Lifetime)
    hasChanged = False

    if 'start-time' in lifetimeParams:
        m = TIME_PATTERN.match(lifetimeParams['start-time'])
        if m is None:
            raise YdkModuleException({'level': 'updateKeyLifetime', 'error': 'invalid lifetime', 'start-time': lifetimeParams['start-time']})
        newHour = int(m.group(1))

        # Allow the optional use of AM/PM at the end of the time and
        # adjust the hour accordingly if present

        if m.group(4):
            if m.group(4).lower() == 'p' and newHour < 13:
                newHour += 12
            if m.group(4).lower() == 'a' and newHour > 12:
                raise YdkModuleException({'level': 'updateKeyLifetime', 'error': 'invalid lifetime', 'start-time': lifetimeParams['start-time']})
        if existingLifetime.start_hour != newHour:
            existingLifetime.start_hour = newHour
            hasChanged = True
        newMinutes = int(m.group(2)) if m.group(2) else 0
        if existingLifetime.start_minutes != newMinutes:
            existingLifetime.start_minutes = newMinutes
            hasChanged = True
        newSeconds = int(m.group(3)) if m.group(3) else 0
        if existingLifetime.start_seconds != newSeconds:
            existingLifetime.start_seconds = newSeconds
            hasChanged = True

    if 'start-date' in lifetimeParams:
        m = DATE_PATTERN.match(lifetimeParams['start-date'].lower())
        if m is None:
            raise YdkModuleException({'level': 'updateKeyLifetime', 'error': 'invalid lifetime', 'start-date': lifetimeParams['start-date']})
        if existingLifetime.start_date != int(m.group(1)):
            existingLifetime.start_date = int(m.group(1))
            hasChanged = True
        newMonth = getEnumByKeyword(Cisco_IOS_XR_lib_keychain_macsec_cfg.MacSecKeyChainMonthEnum, m.group(2))
        if existingLifetime.start_month != newMonth:
            existingLifetime.start_month = newMonth
            hasChanged = True
        if existingLifetime.start_year != int(m.group(3)):
            existingLifetime.start_year = int(m.group(3))
            hasChanged = True

    if 'end-time' in lifetimeParams:
        m = TIME_PATTERN.match(lifetimeParams['end-time'])
        if m is None:
            raise YdkModuleException({'level': 'updateKeyLifetime', 'error': 'invalid lifetime', 'end-time': lifetimeParams['end-time']})
        if existingLifetime.infinite_flag:
            existingLifetime.infinite_flag = False
            hasChanged = True
        newHour = int(m.group(1))

        # Allow the optional use of AM/PM at the end of the time and
        # adjust the hour accordingly if present

        if m.group(4):
            if m.group(4).lower() == 'p' and newHour < 13:
                newHour += 12
            if m.group(4).lower() == 'a' and newHour > 12:
                raise YdkModuleException({'level': 'updateKeyLifetime', 'error': 'invalid lifetime', 'end-time': lifetimeParams['end-time']})
        if existingLifetime.end_hour != newHour:
            existingLifetime.end_hour = newHour
            hasChanged = True
        newMinutes = int(m.group(2)) if m.group(2) else 0
        if existingLifetime.end_minutes != newMinutes:
            existingLifetime.end_minutes = newMinutes
            hasChanged = True
        newSeconds = int(m.group(3)) if m.group(3) else 0
        if existingLifetime.end_seconds != newSeconds:
            existingLifetime.end_seconds = newSeconds
            hasChanged = True

    if 'end-date' in lifetimeParams:
        m = DATE_PATTERN.match(lifetimeParams['end-date'].lower())
        if m is None:
            raise YdkModuleException({'level': 'updateKeyLifetime', 'error': 'invalid lifetime', 'end-date': lifetimeParams['end-date']})
        if existingLifetime.infinite_flag:
            existingLifetime.infinite_flag = False
            hasChanged = True
        if existingLifetime.end_date != int(m.group(1)):
            existingLifetime.end_date = int(m.group(1))
            hasChanged = True
        newMonth = getEnumByKeyword(Cisco_IOS_XR_lib_keychain_macsec_cfg.MacSecKeyChainMonthEnum, m.group(2))
        if existingLifetime.end_month != newMonth:
            existingLifetime.end_month = newMonth
            hasChanged = True
        if existingLifetime.end_year != int(m.group(3)):
            existingLifetime.end_year = int(m.group(3))
            hasChanged = True
    return hasChanged


def createKey(keyId, keyParams):
    newKey = Cisco_IOS_XR_lib_keychain_macsec_cfg.MacSecKeychains.MacSecKeychain.Keies.Key()
    newKey.key_id = keyId
    newKey.key_string = newKey.KeyString()
    newKey.key_string.cryptographic_algorithm = getEnumByKeyword(Cisco_IOS_XR_lib_keychain_macsec_cfg.MacSecCryptoAlgEnum, DEFAULT_CRYPTO)

    if 'key-string' in keyParams:
        newKey.key_string.string = keyParams['key-string']
    if 'algorithm' in keyParams:
        cryptoKeyword = keyParams['algorithm'].lower().replace('-', '_')
        cryptoType = getEnumByKeyword(Cisco_IOS_XR_lib_keychain_macsec_cfg.MacSecCryptoAlgEnum, cryptoKeyword)
        if cryptoType is None:
            raise YdkModuleException({'level': 'createKey', 'error': 'unknown crypto algorithm', 'algorithm': keyParams['algorithm']})
        newKey.key_string.cryptographic_algorithm = cryptoType
    if 'lifetime' in keyParams:
        newKey.lifetime = createKeyLifetime(keyParams['lifetime'])
    return newKey


# Updates the attributes of an existing key

def updateKey(existingKey, keyParams):
    hasChanged = False
    if 'key-string' in keyParams:
        if existingKey.key_string.string != keyParams['key-string']:
            existingKey.key_string.string = keyParams['key-string']
            hasChanged = True
    if 'algorithm' in keyParams:
        cryptoKeyword = keyParams['algorithm'].lower().replace('-', '_')
        cryptoType = getEnumByKeyword(Cisco_IOS_XR_lib_keychain_macsec_cfg.MacSecCryptoAlgEnum, cryptoKeyword)
        if cryptoType is None:
            raise YdkModuleException({'level': 'updateKey', 'error': 'unknown crypto algorithm', 'algorithm': keyParams['algorithm']})
        if existingKey.key_string.cryptographic_algorithm != cryptoType:
            existingKey.key_string.cryptographic_algorithm = cryptoType
            hasChanged = True
    if 'lifetime' in keyParams:
        if updateKeyLifetime(existingKey.lifetime, keyParams['lifetime']):
            hasChanged = True
    return hasChanged


# Create a completely new keychain with all the provided keys

def createKeychain(params):
    # Need to construct the class hierarchy starting at the top. The API MacSecKeychains()
    # constructor creates an empty keychain list

    keychains = Cisco_IOS_XR_lib_keychain_macsec_cfg.MacSecKeychains()
    keychain = keychains.MacSecKeychain()
    keychain.chain_name = params['keychain']

    # Construct any new keys

    if 'keys' in params:
        for keyId, keyParams in params['keys'].items():
            if type(keyParams) is not dict:
                raise YdkModuleException({'level': 'createKeychain', 'error': 'Key parameters expected dictionary'})
            else:
                keychain.keies.key.append(createKey(keyId, keyParams))

    keychains.mac_sec_keychain.append(keychain)
    return keychains


# Runs through all the keys from the playbook and either adds them to an existing
# keychain or updates their attributes if already defined

def updateKeychain(existingKeychain, params):
    hasChanged = False
    if 'keys' in params:
        for keyId, keyParams in params['keys'].items():
            if type(keyParams) is not dict:
                raise YdkModuleException({'level': 'updateKeychain', 'error': 'Key parameters expected dictionary'})
            existingKey = findKeyById(existingKeychain, keyId)
            if existingKey is None:
                existingKeychain.keies.key.append(createKey(keyId, keyParams))
                hasChanged = True
            elif updateKey(existingKey, keyParams):
                    hasChanged = True
    return hasChanged


# statePresent() and stateAbsent() are the two main driving functions

def statePresent(customModule):
    ydkTarget = YDKTarget(**customModule.params['provider'])
    paramChk = ydkTarget.checkParams()
    if paramChk.errFlag:
        customModule.fail_json(msg=paramChk.errMsg, meta={'present': 'checkParams'})

    # Pull the current MACsec keychain operational state

    ydkTarget.connect()
    currentMACSecConfig = ydkTarget.read(Cisco_IOS_XR_lib_keychain_macsec_cfg.MacSecKeychains())

    # If the keychain exists, then there might be modifications

    existingKeychain = findKeychainByName(currentMACSecConfig, customModule.params['keychain'])
    if existingKeychain:
        try:
            hasChanged = updateKeychain(existingKeychain, customModule.params)
            if hasChanged and not customModule.check_mode:
                ydkTarget.update(currentMACSecConfig)
        except YdkModuleException as e:
            ydkTarget.close()
            customModule.fail_json(msg='unable to update keychain', meta=e.yErrorMetaInfo)
        ydkTarget.close()
        return hasChanged, {'keychain': existingKeychain.chain_name}

    # Otherwise the keychain doesn't exist, so create it

    try:
        newKeychain = createKeychain(customModule.params)
        if not customModule.check_mode:
            ydkTarget.create(newKeychain)
    except YdkModuleException as e:
        ydkTarget.close()
        customModule.fail_json(msg='unable to create keychain', meta=e.yErrorMetaInfo)
    ydkTarget.close()
    return True, {'keychain': customModule.params['keychain'], 'state': 'created'}


def stateAbsent(customModule):
    ydkTarget = YDKTarget(**customModule.params['provider'])
    paramChk = ydkTarget.checkParams()
    if paramChk.errFlag:
        customModule.fail_json(msg=paramChk.errMsg, meta={'absent': 'checkParams'})
    else:
        metaInfo = {'keychain': customModule.params['keychain']}

    # Now should be ready to connect to the target device and pick up
    # existing keychain config

    ydkTarget.connect()
    currentMACSecConfig = ydkTarget.read(Cisco_IOS_XR_lib_keychain_macsec_cfg.MacSecKeychains())

    # If the target keychain exists, then just delete the whole thing for now
    # TODO: Allow deletion of individual keys from keychain

    existingKeychain = findKeychainByName(currentMACSecConfig, customModule.params['keychain'])
    if existingKeychain:
        assert isinstance(existingKeychain, Cisco_IOS_XR_lib_keychain_macsec_cfg.MacSecKeychains.MacSecKeychain)
        if not customModule.check_mode:
            # FIXME: Does this delete work on an item in a YList?
            ydkTarget.delete(existingKeychain)
        ydkTarget.close()
        return True, {'keychain': customModule.params['keychain'], 'state': 'removed'}
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
