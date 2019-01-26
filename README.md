# Cumulus HCS Demo Guide

This will walk you through the process of using Cumulus Hyperconverged Service (HCS) on Ravello. 

## Topology

![Topology](./demo_topology.png "Topology")

The topology consists of:

* 3 Nutanix nodes running Nutanix CE configured in a cluster
* 2 Cumulus Linux switches running Cumulus Vx 3.7.3 configured as an MLAG pair
* 1 Cumulus Linux switch (exit01) acting as a jump host to get to and from the environment

### IP Addressing

| Nutanix Node    | KVM IP    | CVM IP    | CVM Port |
| -------------   |----------:| ---------:|---------:|
| NTNX-4e6eac27-A | 10.1.1.10 | 10.1.1.11 | 9441     |
| NTNX-d618a06d-A | 10.1.1.20 | 10.1.1.21 | 9442     |
| NTNX-4e6eac27-A | 10.1.1.30 | 10.1.1.31 | 9443     |

*CVM Cluster IP: 10.1.1.123:9440*

| Leaf   | Loopback IP | CVM Vlan IP    |
| -------|------------:| --------------:|
| leaf01 | 10.0.0.11   | 10.1.1.100     |
| leaf02 | 10.0.0.12   | 10.1.1.200     |

*CVM VRR Gateway IP: 10.1.1.1*


## Cloning the Ravello Blueprint

_TODO_

## Starting the lab
From the Ravello canvas you will see the 3 nutanix nodes, two leafs and exit.
![Canvas](./ravello_images/canvas.png "Canvas")

### Verify Nutanix VM Requirements
In order to run Nutanix CE on Ravello, you must enable nested virtualization on bare metal hosts. 
![General Settings](./ravello_images/nutanix_settings.png "General Settings")<br />
To do this, select the Nutanix VM then on the right hand menu select `General` and then click the link at the bottom of the pane `Advanced Configuration`

![Advanced Configuration](./ravello_images/advanced_configuration.png "Advanced Configuration")<br />
Set `cpu-model` to *SandbyBridge* 
Set `preferPhysicalHost` to *true* _If you do not see this setting, open a case with Ravello support to enable it_ 
Click `OK` 
And then click `Save` when back on the right pane. 
 
Repeat this on all three Nutanix nodes. There are no settings to modify on either of the leaf nodes or the exit node.

### Start the Lab
Now the lab blueprint must be "published" to a Ravello datacenter.
![Publish Box](./ravello_images/publish.png "Publish Box")<br />

Ravello gives the option of "Optimize for Cost" or "Optimize for Performance". Select `Performance`. 
Choose the location geographically closest to you.

Then click *Publish*. 
_Note: This lab will cost around $7/hr on Ravello due to the CPU and memory requirements of Nutanix AHV._
 
It will take 10 minutes or more for Ravello to copy all of the disk images and fully publish your lab. 
![Publish Box](./ravello_images/publish_waiting.png "Publish Box")<br />
During this time you will see hourglass icons on all of the VMs while they boot. 

When all VMs have started the hourglass icon will be replaced with a green play button
![VMs Started](./ravello_images/green_arrow.png "VMs Started")

### Access the Lab
When the lab is running you can SSH to the "exit" device. 

![IP Address](./ravello_images/ravello_ip.png "IP Address")<br />

Look at the right "Summary" panel for "VM is started" and use the IP in that box to SSH to.

![SSH to the Exit node](./ravello_images/ssh_exit.png "SSH to the Exit node")<br />

SSH to the "exit" node and login with  
username: `cumulus`  
password: `CumulusLinux!` 

![SSH](./ravello_images/ssh_exit.png "SSH")<br />

From the exit node you can ssh to either `leaf01` or `leaf02`. 
If you wish to access the Nutanix console you can also ssh to any Nutanix IP address. The Nutanix nodes use the following credentails
KVM host username: `root`  
KVM host password: `nutanix/4u`  
 
CVM host SSH username: `nutanix`  
CVM host SSH password: `nutanix/4u`

From `leaf01` view that the Nutanix nodes have been discovered via LLDP
```Shell
cumulus@leaf01:~$ net show lldp

LocalPort  Speed  Mode           RemoteHost       RemotePort
---------  -----  -------------  ---------------  ----------
eth0       1G     Mgmt           leaf02           eth0
swp1       1G     BondMember     NTNX-e08c61ec-A  ens3
swp2       1G     BondMember     NTNX-d618a06d-A  ens3
swp3       1G     BondMember     NTNX-4e6eac27-A  ens3
swp49      1G     BondMember     leaf02           swp49
swp50      1G     BondMember     leaf02           swp50
swp51      1G     NotConfigured  exit             swp1
```

You can also view the dynamically created bonds
```Shell
cumulus@leaf01:~$ net show interface bonds
    Name       Speed   MTU  Mode     Summary
--  ---------  -----  ----  -------  ----------------------------------
UP  bond_swp1  1G     1500  802.3ad  Bond Members: swp1(UP)
UP  bond_swp2  1G     1500  802.3ad  Bond Members: swp2(UP)
UP  bond_swp3  1G     1500  802.3ad  Bond Members: swp3(UP)
UP  peerlink   2G     1500  802.3ad  Bond Members: swp49(UP), swp50(UP)
```

View that MLAG (or Cumulus mLAG) is up and that these three bonds have been assigned `CLAG IDs`
```Shell
cumulus@leaf01:~$ net show clag
The peer is alive
     Our Priority, ID, and Role: 1000 44:38:39:00:01:49 primary
    Peer Priority, ID, and Role: 1000 44:38:39:00:02:49 secondary
          Peer Interface and IP: peerlink.4094 fe80::4638:39ff:fe00:249 (linklocal)
                      Backup IP:  (inactive)
                     System MAC: 44:38:39:ff:40:00

CLAG Interfaces
Our Interface      Peer Interface     CLAG Id   Conflicts              Proto-Down Reason
----------------   ----------------   -------   --------------------   -----------------
       bond_swp1   -                  9979      -                      -
       bond_swp3   -                  60756     -                      -
       bond_swp2   -                  7773      -                      -
```


Finally, view that only VLAN 1 has been programmed in the spanning-tree bridge 
```Shell
cumulus@leaf01:~$ net show bridge vlan

Interface  VLAN  Flags
---------  ----  ---------------------
bond_swp1     1  PVID, Egress Untagged
bond_swp2     1  PVID, Egress Untagged
bond_swp3     1  PVID, Egress Untagged
bridge        1
peerlink      1  PVID, Egress Untagged
```

You may repeat the same steps on `leaf02` to verify that the state of the network is the same on both leafs.

### Access Nutanix Prism
The same IP address we used to SSH to the `exit` node will be used to access the Prism web GUI. 

![IP Address](./ravello_images/ravello_ip.png "IP Address")<br />

Again, from the Ravello canvas, look at the right "Summary" panel for "VM is started" and use the IP in that box.  
Connect to `https://<IP_ADDRESS>:9440`

You will receive a warning about the connection not being secure or about the SSL certificate.

![SSL Warning](./ravello_images/ssh_warning.png "SSL Warning")<br />

Depending on the browser, click advanced and "Continue" or ignore or whatever is the proper conf

![Prism Login](./ravello_images/nutanix_login.png "Prism Login")<br />

_Note:_ The Prism services may take 10-15 minutes to start *after* the Nutanix VMs are online. Attempting to access the URL before the Prism services are online will result in an error that the page can not be found or `Oops - Server Error` message.

_Note:_ Prism is only accessable via *HTTPS* and will not redirect from HTTP. If you access the Prism IP via HTTP you will receive an `Oops - Server Error` message.

At the login screen you can login with  
username: `admin`  
password: `1CumulusLinux!`  