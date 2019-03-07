# __xrvr9k container__


Content here originally utlized for 2017 DEVNET_1223 Workshop: Automating IOS-XR with Ansible
    Co-authored with Tim Thomas
    Reference: https://github.com/tithomas1/DEVNET-1223 
    
    
    
## Setting up IOS-XR to allow Ansible

If not done already, generate crypto keys on the target IOS-XR device:

```commandline
crypto key generate rsa
```

Enable SSH version 2 and set a reasonable timeout:

```commandline
config t
  ssh version v2
  ssh timeout 120
  commit
  exit
```

This should be enough to try a simple command from your Ansible host. Make sure the target
device is already defined in your inventory. In this case, we'll use the *raw* command as
a test to pass a command over SSH to the IOS-XR CLI and dump the output. The `-u` parameter
specifies the SSH username, the `-k` parameter will trigger a prompt for the SSH password,
the `-m` specifies to use the *raw* command, and the `-a` provides the arguments to the
command/module.

```commandline
ansible <host> -u <username> -k -m raw -a "show version"
```

The first time you'll have to accept the SSH keys. You can also set up IOS-XR to use
certificate-based authentication for SSH, but that's outside the scope of this README at
the moment.

### Example playbooks
Set an SNMP community string:
```commandline
ansible-playbook playbooks/set-snmpv2.yaml --extra-vars="community=cisco123”
```
Create a new user account:
```commandline
ansible-playbook playbooks/create_user.yaml --extra-vars="newuser=bob password=cisco"
```
Delete an existing user:
```commandline
ansible-playbook playbooks/delete_user.yaml --extra-vars="user=bob"
```

<<<<<<< HEAD
=======
## Setting up IOS-XR to allow NETCONF access (for YDK)

Allow NETCONF over SSH:

```commandline
config t
  ssh server netconf vrf default
  ssh server netconf port 830
  netconf-yang agent ssh
  commit
  exit
```

## Using YDK-Gen to create custom APIs

YDK's `generate` tool can be used to create custom/targeted APIs for specific use cases. Or it
might also be needed if a particular model isn't included in what comes with YDK (like the
IETF or OpenConfig models). I ended up needing to do my own because the OpenConfig interfaces
model wasn't included.

First, you need some tools on a build server. I used Ubuntu 16.04:

```commandline
sudo apt-get install python-pip zlib1g-dev python-lxml libxml2-dev libxslt1-dev python-dev libboost-dev libboost-python-dev \
  libssh-dev libcurl4-openssl-dev libtool-bin libboost-all-dev libboost-log-dev libpcre3-dev libpcre++-dev libtool pkg-config \
  python3-dev python3-lxml cmake
```

Then you need to clone the YDK-Gen repository to a location on that server:

```commandline
mkdir -p ~/projects/ydk
cd ~/projects/ydk
git clone https://github.com/CiscoDevNet/ydk-gen
cd ydk-gen
```

Doing this in a virtual environment is not a bad idea, but you'll need to override where
Ansible looks for the default Python interpreter. Otherwise, the generated API will need
to be present in the global package list. We'll get to more on that later.

```commandline
virtualenv -p python2.7 venv
source venv/bin/activate
```
Install YDK-Gen's module dependencies into the virtual environment (this will take a bit):

```commandline
pip install -r requirements.txt
```
Now `generate` should work. As a test:

```commandline
./generate.py --help
```
Generate the core API and install it:

```commandline
./generate.py --python --core
pip install gen-api/python/ydk/dist/ydk*.tar.gz
```
Create an API bundle description. You can use the OSPF or MACsec ones included in this repository as examples:

```commandline
vi profiles/bundles/ciscolive-ansible-ospf.json
```
Now we're ready to generate an API from the bundle description:

```commandline
./generate.py --python --bundle profiles/bundles/ciscolive-ansible-ospf.json
```
You can install the generated API into the virtual environment as a test or if you're planning to use the
API for something other than Ansible:

```commandline
pip install gen-api/python/ciscolive_ansible_ospf-bundle/dist/ydk*.tar.gz
```
If you're ready to try Ansible + YDK, you can override where Ansible looks for the default Python
interpreter in the virtual environment. Add the following to the inventory:

```commandline
[vars:all]
ansible_python_interpreter="/usr/bin/env python"
```

Now you can install YDK and your custom API (if any):

```commandline
pip install -r requirements.txt
pip install gen-api/python/ydk/dist/ydk*.tar.gz
pip install gen-api/python/ciscolive_ansible_ospf-bundle/dist/ydk*.tar.gz
```

If you don't want to use a virtual environment, then just install YDK and your custom API in the
global package list:

```commandline
deactivate
sudo pip install -r requirements.txt
sudo pip install gen-api/python/ydk/dist/ydk*.tar.gz
sudo pip install gen-api/python/ciscolive_ansible_ospf-bundle/dist/ydk*.tar.gz
```
>>>>>>> origin/master
