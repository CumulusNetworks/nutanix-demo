# Cumulus HCS Demo Guide
This will walk you through the process of using Cumulus Hyperconverged Service (HCS) on Ravello. 

## Topology
![Topology](./demo_topology.png "Topology")

The topology consists of:
* 3 Nutanix nodes (NTNX-e08c61ec-A, NTNX-d618a06d-A, NTNX-4e6eac27-A) running Nutanix CE configured in a cluster
* 2 Cumulus Linux switches (leaf01, leaf02) configured as an MLAG pair
* 1 Cumulus Linux switch (exit01) acting as a jump host to get to and from the environment

### IP Addressing
**Nutanix Nodes**
* NTNX-4e6eac27-A KVM host: 10.1.1.10
* NTNX-4e6eac27-A CVM: 10.1.1.11

* NTNX-d618a06d-A KVM host: 10.1.1.20
* NTNX-d618a06d-A CVM: 10.1.1.21

* NTNX-4e6eac27-A KVM host: 10.1.1.30
* NTNX-4e6eac27-A CVM: 10.1.1.31

_CVM Cluster IP: 10.1.1.123_

** Network Devices**
** leaf01: 10.0.0.11 (lo), 10.1.1.100/24 (Vlan1), 10.1.1.1/24 (VRR Gateway Address)
** leaf02: 10.0.0.12 (lo), 10.1.1.200/24 (Vlan1), 10.1.1.1/24 (VRR Gateway Address)

