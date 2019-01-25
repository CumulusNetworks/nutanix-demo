# Cumulus HCS Demo Guide

This will walk you through the process of using Cumulus Hyperconverged Service (HCS) on Ravello. 

## Topology

![Topology](./demo_topology.png "Topology")

The topology consists of:

* 3 Nutanix nodes (NTNX-e08c61ec-A, NTNX-d618a06d-A, NTNX-4e6eac27-A) running Nutanix CE configured in a cluster
* 2 Cumulus Linux switches (leaf01, leaf02) configured as an MLAG pair
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
