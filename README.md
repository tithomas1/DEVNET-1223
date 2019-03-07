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

