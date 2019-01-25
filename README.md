# Cumulus HCS Demo Guide

This will walk you through the process of using Cumulus Hyperconverged Service (HCS) on Ravello. 

## Topology

![Topology](./demo_topology.png "Topology")

The topology consists of:

* 3 Nutanix nodes running Nutanix CE configured in a cluster
* 2 Cumulus Linux switches running Cumulus Vx 3.7.3 configured as an MLAG pair
* 1 Cumulus Linux switch (exit01) acting as a jump host to get to and from the environment

### IP Addressing

| Nutanix Node    | KVM IP    | CVM IP    |
| -------------   |----------:| ---------:|
| NTNX-4e6eac27-A | 10.1.1.10 | 10.1.1.11 |
| NTNX-d618a06d-A | 10.1.1.20 | 10.1.1.21 |
| NTNX-4e6eac27-A | 10.1.1.30 | 10.1.1.31 |

*CVM Cluster IP: 10.1.1.123*

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
![General Settings](./ravello_images/nutanix_settings.png "General Settings")
To do this, select the Nutanix VM then on the right hand menu select `General` and then click the link at the bottom of the pane `Advanced Configuration`

![Advanced Configuration](./ravello_images/advanced_configuration.png "Advanced Configuration")
Set `cpu-model` to *SandbyBridge*
Set `preferPhysicalHost` to *true* _If you do not see this setting, open a case with Ravello support to enable it_
Click `OK`
And then click `Save` when back on the right pane.

Repeat this on all three Nutanix nodes. There are no settings to modify on either of the leaf nodes or the exit node.

### Start the Lab
Now the lab blueprint must be "published" to a Ravello datacenter.
![Publish Box](./ravello_images/publish.png "Publish Box")

Ravello gives the option of "Optimize for Cost" or "Optimize for Performance". Select `Performance`. 
Choose the location geographically closest to you.

Then click *Publish*.
_Note: This lab will cost around $7/hr on Ravello due to the CPU and memory requirements of Nutanix AHV._

It will take some time for Ravello to copy all of the disk images and fully publish your lab. 
![Publish Box](./ravello_images/publish_waiting.png "Publish Box")
During this time you will see hourglass icons on all of the VMs while they boot. 

