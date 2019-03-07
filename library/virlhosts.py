#!/usr/bin/env python3

"""
   Name: virlhosts.py
   version: 1.0, March 6, 2019
   by joerober@cisco.com

   Purpose:
        Script get VIRL Simulation node_name and management ip address
        and write to a hosts file

   assumptions, notes:
        -Valid user and password for VIRL Server (e.g. VIRL running on ESXi)
        -Script uses VIRL Server on port 19399 for VIRL STD API Calls
        -Reference: http://<virl_server>/docs/api/std/
        -User running single simulation

   ZERO ERROR HANDLING IN THIS VERSION

   USER ASSUMES ALL RESPONSIBILITY

"""

import requests
from argparse import ArgumentParser, RawTextHelpFormatter
import getpass

class Hosts:

    # static attributes (for parsing):
    mgt = 'management'
    ip_key = 'ip-address'

    def __init__(self, user, passwd, file, server):
        self.user=user
        self.passwd=passwd
        self.server=server
        self.file=file
        self.url='http://' + server + ':19399/simengine/rest/'

    def __str__(self):
        return 'User: {0}\nFile: {1}\nSTD API: {2}'.format(self.user, self.file, self.url)

    def simName(self):

        sim_req = requests.get(self.url + 'list', auth=(self.user, self.passwd))
        siminfo=sim_req.json()

        for key in siminfo['simulations'].keys():
            simname=key

        return simname

    def get_nodes(self, simName):
        # get nodes:
        node_req = requests.get(self.url + 'nodes/' + simName, auth=(self.user, self.passwd))
        node_list = node_req.json()[simName].keys()

        # simple list for just the node names
        nodes = []

        # move dict_keys into a list:
        for i in node_list:
            nodes.append(i)

        return nodes

    def getIntWriteInt(self, simName, nodes):
        mgt='management'
        ip_key='ip-address'

        # get list of interfaces in simulation:
        int_req = requests.get(self.url + 'interfaces/' + simName, auth=(self.user, self.passwd))
        int_list = int_req.json()

        # append to file as 'ip_address    node' per line
        with open(self.file, 'a') as f:
            for node in nodes:
                f.write(int_list[simName][node][mgt][ip_key].split('/')[0] + '    ' + node + '\n')

        return 'get and write complete'

def main():

    # arguments
    parser = ArgumentParser(formatter_class=RawTextHelpFormatter,
                            prog='virlhosts.py',
                            description='''Purpose is to get virl simulation management ip address and write to a file (e.g. /etc/hosts)''')

    parser.add_argument('-u', help='virl server username', required=True, dest='user', type=str)
    parser.add_argument('-s', help='virl server ip address/dns name', required=True, dest='server', type=str)
    parser.add_argument('-f', help='file to append simulation management ip and node', required=True, dest='file', type=str)

    args = parser.parse_args()

    assert isinstance(args.user, str)
    assert isinstance(args.server, str)
    assert isinstance(args.file, str)

    password=getpass.getpass(prompt='Enter virl user password: ', stream=None)

    print(args.user + '\n' + args.server + '\n' + args.file + '\n' + password)

    # instantiate Hosts with args
    hosts = Hosts(args.user, password, args.file, args.server)

    # get simulation name
    sim=hosts.simName()
    # use simulation name to get list of nodes
    node_list=hosts.get_nodes(sim)
    # use simulation name and node_list to get node interfaces, management ip address
    # and write to file
    result=hosts.getIntWriteInt(sim, node_list)
    print(result)


if __name__=='__main__':
    main()