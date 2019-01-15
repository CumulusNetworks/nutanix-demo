#!/usr/bin/env python3
# CUMULUS-AUTOPROVISIONING

# Copyright (C) 2019 Cumulus Networks, Inc. All rights reserved
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
# CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
# TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
# https://www.debian.org/legal/licenses/mit
#

import subprocess
import os
import json
import time
import socket

USERNAME = None
PASSWORD = None
CLUSTER_IP = None
MANAGEMENT_IP = None
UPLINKS = None
GATEWAY = None
PEERLINK = "swp49,swp50"

if "ZTP_USB_MOUNTPOINT" in os.environ:
    ZTP = os.environ.get("ZTP_USB_MOUNTPOINT")
else:
    print("Unable to determine where this ZTP script lives. Exiting")
    exit(1)


def check_license():
    '''
    Check if the switch is licensed
    '''
    # cl-license returns 0 if the license is installed
    return subprocess.Popen(["cl-license",], stdout=subprocess.PIPE).returncode == 0


def install_license():
    '''
    install a Cumulus license
    '''
    subprocess.Popen(["cl-license", "-i", ZTP + "license.txt"], stdout=subprocess.PIPE)

    if check_license():
        print("Error installing license, please double check that the license.txt file is valid")
        exit(1)

    subprocess.Popen(["systemctl", "reset-failed", "switchd.service"], stdout=subprocess.PIPE)
    subprocess.Popen(["systemctl", "restart", "switchd.service"], stdout=subprocess.PIPE)

    proc = subprocess.Popen(["systemctl", "is-active", "switchd.service"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if proc.returncode != 0:
        print("Unable to start switchd after applying a license."
              + " Please view \"journalctl -u switchd.service\" for more information. Exiting.")
    exit(1)


def check_nclu_ready():
    '''
    Check if NCLU and netd are ready
    '''
    return subprocess.Popen(["net", "show", "interface"], stdout=subprocess.PIPE).returncode == 0


def get_interfaces():
    '''
    Get a json list of the interfaces. Expects NCLU to be running
    '''
    proc = subprocess.Popen(["net", "show", "interface", "json"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    err = proc.communicate()[1]

    if proc.returncode != 0:
        print("Problem fetching interfaces. Maybe an issue with NCLU? " + err)
        exit(1)

    return json.loads(proc.communicate()[0])


def set_swp_mtu(interfaces):
    '''
    Set the MTU of all swp ports on the box to 9000
    '''
    interface_line = []

    for interface in interfaces():
        if interface[:3] == "swp":
            interface_line.append(interface)

    proc = subprocess.Popen(["net", "add", "interface", ",".join(
        interface_line), "mtu", "9000"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    err = proc.communicate()[1]

    if proc.returncode == 0:
        return True
    else:
        print("Encounter an error setting MTU. " + str(err))
        exit(1)


def enable_mgmt_vrf():
    '''
    Enable management VRF and set the MANAGEMENT_IP if defined
    '''
    proc = subprocess.Popen(["net", "add", "vrf", "mgmt"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    if proc.returncode != 0:
        print("Encountered an error configuring management VRF. " + str(proc.communicate()[1]))
        exit(1)

    if MANAGEMENT_IP:
        proc = subprocess.Popen(["net", "add", "interface", "eth0", "ip", "address",
                                 MANAGEMENT_IP], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        if proc.returncode != 0:
            print("Encountered an error assigning IP address " +
                  MANAGEMENT_IP + " to eth0. " + str(proc.communicate()[1]))
        exit(1)

        if GATEWAY:
            proc = subprocess.Popen(["net", "add", "routing", "route", "0.0.0.0/0",
                                     GATEWAY, "vrf", "mgmt"],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            if proc.returncode != 0:
                print("Encountered an error assigning the default gateway " + GATEWAY +
                      " to the management interface." + str(proc.communicate()[1]))
            exit(1)


def load_config():
    '''
    Load the ZTP configuration file to define paramaters
    '''
    global USERNAME
    global PASSWORD
    global CLUSTER_IP
    global MANAGEMENT_IP
    global UPLINKS
    global GATEWAY
    global PEERLINK

    try:
        file = open(ZTP + "ztp_config.txt")
    except IOError:
        print("Unable to open ztp_config.txt file. Exiting")
        exit(1)

    with file:
        for line in file:
            line = line.strip()
            split = line.strip().split("=")
            if len(split) <= 1:
                continue
            key = split[0].upper()
            value = split[1]
            if key == "NUTANIX_USERNAME":
                USERNAME = value
            if key == "NUTANIX_PASSWORD":
                PASSWORD = value
            if key == "NUTANIX_IP":
                CLUSTER_IP = value
            if key == "SWITCH_MANAGEMENT_IP":
                MANAGEMENT_IP = value
            if key == "UPLINKS":
                UPLINKS = value
            if key == "SWITCH_DEFAULT_GATEWAY":
                GATEWAY = value
            if key == "PEERLINK":
                PEERLINK = value

    if not USERNAME:
        error = "NUTANIX_USERNAME"
    if not PASSWORD:
        error = "NUTANIX_PASSWORD"
    if not CLUSTER_IP:
        error = "NUTANIX_IP"

    if error:
        print(error + " not defined in the ztp_config.txt file. Exiting")
        exit(1)

    try:
        socket.inet_aton(CLUSTER_IP)
    except socket.error:
        print("Invalid NUTANIX_IP. Exiting")
        exit(1)

    return True


def build_nutanix_config():
    '''
    Produce the cumulus-hyperconverged configuration file
    '''

    output_lines = []
    output_lines.append("### /etc/default/cumulus-hyperconverged config file")
    output_lines.append("# username for Prism (required)")
    output_lines.append("USERNAME=" + USERNAME)
    output_lines.append("# password for Prism (required)")
    output_lines.append("PASSWORD=" + PASSWORD)
    output_lines.append("# CVM address used by the service (required)")
    output_lines.append("SERVER=" + CLUSTER_IP)
    output_lines.append("# single/multi rack configuration (optional)")
    output_lines.append("VXLAN_CONFIG=False")
    output_lines.append("")

    try:
        file = open("/usr/default/cumulus-hyperconverged", "w+")
    except IOError:
        print("Unable to open Cumulus HCS file /usr/default/cumulus-hyperconverged. Exiting")
        exit(1)

    file.write("\n".join(output_lines))
    file.close()


def configure_uplinks():
    """
    Put all of the uplinks in the bridge
    Assign all VLANs to the bridge
    """
    for interface in UPLINKS.split(","):
        if interface[:3] != "swp":
            print("Invalid interface in UPLINK list. Exiting")
            exit(1)

    proc = subprocess.Popen(["net", "add", "bridge", "bridge", "ports",
                             UPLINKS], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    if proc.returncode != 0:
        print("Encountered an error placing uplink interfaces " +
              UPLINKS + " into a bridge. " + str(proc.communicate()[1]))
    exit(1)

    proc = subprocess.Popen(["net", "add", "bridge", "bridge", "vids",
                             "1-2999"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if proc.returncode != 0:
        print("Encountered an error adding VLANs 1-2999. " +
              str(proc.communicate()[1]))
    exit(1)

    proc = subprocess.Popen(["net", "add", "bridge", "bridge", "vids",
                             "4000-4095"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if proc.returncode != 0:
        print("Encountered an error adding VLANs 4000-4095. " +
              str(proc.communicate()[1]))
    exit(1)


def enable_hyperconverged_service():
    '''
    Start the cumulus-hyperconverged service at boot time
    and start it right now
    '''
    subprocess.Popen(["systemctl", "enable", "cumulus-hyperconverged.service"],
                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    subprocess.Popen(["systemctl", "start", "cumulus-hyperconverged.service"],
                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    proc = subprocess.Popen(["systemctl", "is-active", "cumulus-hyperconverged.service"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if proc.returncode != 0:
        print("Encountered an error enabling cumulus-hyperconverged.service. "
              + "Please check \"journalctl -u cumulus-hyperconverged.service\""
              + "for more information")
    exit(1)


def enable_clag():
    '''
    Enable CLAG on the defined PEERLINK ports.
    The default ports are swp49 and swp50.
    If the ports provided do not exist on the switch
    (or if the switch doesn't have a swp49 or swp50)
    ifreload -a will fail and the ZTP script will produce an error and exit
    '''

    peerlink_bond = " ".join(PEERLINK.split(","))
    clag_lines = []
    clag_lines.append("auto peerlink")
    clag_lines.append("iface peerlink")
    clag_lines.append("  bond-slaves " + peerlink_bond)
    clag_lines.append("")
    clag_lines.append("auto peerlink.4094")
    clag_lines.append("iface peerlink.4094")
    clag_lines.append("   clagd-peer-ip linklocal")
    clag_lines.append("   clagd-sys-mac 44:38:39:FF:40:00")
    clag_lines.append("")
    clag_lines.append("auto bridge")
    clag_lines.append("iface bridge")
    clag_lines.append("    bridge-ports peerlink")
    clag_lines.append("    bridge-vids 1")
    clag_lines.append("    bridge-vlan-aware yes")

    try:
        file = open("/etc/network/interfaces", "a+")
    except IOError:
        print("Unable to open /etc/network/interfaces file. Exiting")
        exit(1)

    file.write("\n".join(clag_lines))
    file.close()

    proc = subprocess.Popen(["ifreload", "-a"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    if proc.returncode != 0:
        print("Unable to apply peerlink interface configuration, "
              + "verify that the peerlink ports exist. Exiting. " + proc.communicate()[1])
    exit(1)


def place_ntp_in_vrf():
    '''
    Move NTP to the management VRF
    '''

    subprocess.Popen(["systemctl", "stop", "ntp.service"],
                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    subprocess.Popen(["systemctl", "disable", "ntp.service"],
                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    subprocess.Popen(["systemctl", "start", "ntp@mgmt.service"],
                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    subprocess.Popen(["systemctl", "enable", "ntp@mgmt.service"],
                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def apply_nclu_config():
    '''
    Run "net commit"
    '''
    proc = subprocess.Popen(["net", "commit"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if proc.returncode != 0:
        print("Encountered an error applying NCLU configuration. Exiting. " + proc.communicate()[1])
    exit(1)


if __name__ == '__main__':
    # TODO: Check for CL 3.7.2 or later.

    load_config()
    install_license()

    # CLAG must be enabled before NCLU commands so that the /e/n/i config is in place
    enable_clag()
    while check_nclu_ready:
        time.sleep(1)

    set_swp_mtu(get_interfaces())
    enable_mgmt_vrf()
    configure_uplinks()
    enable_hyperconverged_service()
    apply_nclu_config()

    # NTP config must happen after NCLU is applied
    place_ntp_in_vrf()

    exit(0)
