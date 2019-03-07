#!/usr/bin/python

# Author:  Joel Roberts (joerober@cisco.com) 
# Created: 7/7/17
# Version: 1.0 
#
# Provides functions to add k9-sec.pie to an IOS XR device: 
# 	*install add <k9sec.pie> activate
# 	install verify packages
#	install commit
#	configures crypto keys
#	adds sshv2 configuration 
#
#       *this requires assumes tftp server with appropriate k9-sec image 
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

import sys
from collections import namedtuple


addK9ParamError = namedtuple('addK9ParamError', ['errFlag', 'errMsg'])


class conTelnet():
    import telnetlib

    def __init__(self,host,username,password):
        self.host=host
        self.username=username
        self.password=password

    def info(self):
        return [self.host, self.username, self.password]

    def checkParams(self, params):
        if 'host' not in params:
            return addK9ParamError(True, 'missing host parameter')
        else:
            self.host=params['host']
        if 'username' not in params:
            return addK9ParamError(True, 'missing username parameter')
        else:
            self.username=params['username']
        if 'password' not in params:
            return addK9ParamError(True, 'missing password parameter')
        else:
            self.password=params['password']
        return addK9ParamError(False, 'ok')

    def connectHost(self):
        user_enter=self.username+"\n"
        pw_enter=self.password+"\n"

        self.tn= self.telnetlib.Telnet(self.host)
        print self.tn.read_until("Username:")
        self.tn.write(user_enter)

        print self.tn.read_until("Password:")
        self.tn.write(pw_enter)

        return self.tn

    def close(self):
        return self.tn.close()

    def show_command(self):
        command="show crypto key mypub rsa"
        self.tn.write(command.encode('ascii')+'\n')
        return self.tn.read_until(self.host+"#")

    def setAdmin(self):
        self.tn.write("admin\n")
        print self.tn.read_until(self.host+"(admin)")

    def exitAdmin(self):
        self.tn.write("exit\n\n")
        print self.tn.read_until(self.host+"#")

    # action: take the tftp: server and file image as an argument (from the module) 
    def installAddActivate(self):
        self.tn.write("install add tftp://172.16.2.47/xrvr-k9sec-x.pie-6.2.2 activate\n")
        print "install add activate started\n"
        print self.tn.read_until("Part 2 of 2 (activate software): Completed successfully")

        self.tn.write("show install request\n")
        print self.tn.read_until(self.host + "(admin)#")
        print "\ninstall add activate complete\n"

    def installVerifyPackages(self):
        self.tn.write("install verify packages\n")
        print "Install verify started....this takes awhile... "
        print self.tn.read_until("Info:         The system needs no repair.")

        self.tn.write("show install request\n")
        print self.tn.read_until(self.host + "(admin)#")

    def installCommit(self):
        self.tn.write("install commit\n")
        print "Install commit started\n"
        print self.tn.read_until("completed successfully")

        self.tn.write("show install request\n")
        print self.tn.read_until(self.host+"(admin)#")

    def setConfT(self):
        self.tn.write("configure terminal\n")
        print self.tn.read_until(self.host+"(config)#")

    def exitConfT(self):
        self.tn.write("exit\n")

    def confCommand(self,command):
        self.tn.write(command.encode('ascii')+"\n")
        print self.tn.read_until(self.host+"(config)#")

    def telnetCommand(self,command):
        self.tn.write(command.encode('ascii')+"\n")
        print self.tn.read_until(self.host+"#")

    def createKeys(self):
        rsa_cmd="crypto key generate rsa"
        dsa_cmd="crypto key generate dsa"
        show_rsa="show crypto key mypubkey rsa"
        show_dsa="show crypto key mypubkey dsa"
        commands=[show_rsa, show_dsa]

        self.tn.write(rsa_cmd+"\n")
        print self.tn.read_until("modulus")
        self.tn.write("\n")
        print self.tn.read_until(self.host+"#")

        self.tn.write(dsa_cmd+"\n")
        print self.tn.read_until("modulus")
        self.tn.write("\n")
        print self.tn.read_until(self.host+"#")
        for cmd in commands:
            self.telnetCommand(cmd)

    def configSsh(self):
        sshConfig=["domain name cisco.com", "ssh client vrf default", "ssh server v2", "ssh server vrf default"]
        for cmd in sshConfig:
            self.confCommand(cmd)
        self.tn.write("commit\n")
        print self.tn.read_until(self.host+"(config)#")

    def addSecPie(self):
        self.setAdmin()
        self.installAddActivate()
        self.installVerifyPackages()
        self.installCommit()
        self.exitAdmin()

    def addCryptoSsh(self):
        self.createKeys()
        self.setConfT()
        self.configSsh()
        self.exitConfT()
        print "done with config t exit\n" 

# END CLASS
