#!/usr/bin/python

#*******************************************************************************
#
#  @file    cumulus-hyperconverged
#  @brief   This file is for testing out the Nutanix webhooks interface
#
#  @copyright Copyright (C) 2018 Cumulus Networks, Inc. All rights reserved
#
#  @remark  This software is subject to the Cumulus Networks End User License
#           Agreement available  at the following locations:
#
#  @remark  Internet: https://cumulusnetworks.com/downloads/eula/latest/view/
#
#  @remark  Cumulus Linux systems: /usr/share/cumulus/EULA.txt
#
#*******************************************************************************

#-------------------------------------------------------------------------------
#
#   Imports
#
#-------------------------------------------------------------------------------

# Standard library imports
import base64
import BaseHTTPServer
import clag.clagdcmd
import json
import logging
import logging.handlers
import nlmanager.nllistener
import nlmanager.nlmanager
import nlmanager.nlpacket
import pprint
import Queue
import signal
import socket
import struct
import ssl
import subprocess
import sys
import threading
import time
import traceback
import urllib2


#-------------------------------------------------------------------------------
#
#   Constants
#
#-------------------------------------------------------------------------------

_NLM_INTF = 3
_NLM_WORKQ = 4
_NLM_STOP = 5


#-------------------------------------------------------------------------------
#
#   Global variables
#
#-------------------------------------------------------------------------------

username = None
password = None
server = None
hook_server = None
hook_port = 8888
socket_timeout = 30
loglevel = None
vxlan_config = True
vxlan_local_ip = None
periodic_sync_timeout = 60
parser = None
logger = logging.getLogger("cumulus-hyperconverged")
ipmi_bypass = False
lldp_del_ignore = []
pp = pprint.PrettyPrinter(indent=4)
wq = None
lldp_monitor = None
wh = None
wh_uuid = None
http_server = None
subnets = None
hosts = None
vms = None
ntnx_rest_api = None
api_library = None
periodic_sync = None
listener = None
Intf = None

#
#   This dictionary keeps track of automatically added bonds. The key is the name
#   of an automatically added bond interface. The value is a tuple containing the
#   a flag if the bond was automatically added, clag ID assigned to the bond, a
#   list of slave interfaces, the name of the bridge to which the bond was added,
#   and the name of the LLDP neighbor host.
#
#   { 'bond_swp1s0' : ( True, 62313, ['swp1s0'], 'bridge', 'NTNX-4b620705-A' ),
#     'bond_swp1s1' : ( True, 36321, ['swp1s1'], 'bridge', 'NTNX-6ae35732-A' ), ... }
#
autobonds = {}
autobondsLock = threading.Lock()

#
#   This dictionnay keeps track of configured vlan. The key is the vlan id. The
#   value is a list containing the number of VMs in that vlan, a nested dict
#   that contains the bond name as key (and the number of VMs for that bond and
#   a flag if the vlan was previously to the bond), a flag if the vlan was added
#   to the peerlink, a flag if the vlan was added to the bridge and a flag if
#   the vxlan device was automatically added.
#   { '100' : [ 5, { 'bond_swp1s0': ['3', False],
#                    'bond_swp1s1': ['2', False] },
#               False, False, False ]
#   }
vlanDB = {}
vlanDBLock = threading.Lock()

#
#   This dictionnary keeps track of the active VMs. The key is the unique ID of
#   the VM and the value is a tuple containing the bond, the vlan ID, the
#   hotname of the server, the VM name and the mac address.
#   { uuid : ( bondname, vlan, hostname, vm_name, mac )
#   }
vmDB = {}
vmDBLock = threading.Lock()

#-------------------------------------------------------------------------------
#
#   Classes
#
#-------------------------------------------------------------------------------

class NetlinkListener(nlmanager.nllistener.NetlinkManagerWithListener):
    def __init__(self):
        self.keep_going = True

        self.groups = nlmanager.nlpacket.RTMGRP_LINK | \
                      nlmanager.nlpacket.RTMGRP_IPV4_IFADDR | \
                      nlmanager.nlpacket.RTMGRP_IPV6_IFADDR
        super(NetlinkListener, self).__init__(self.groups)
        self.Intf = Intf

    def stop(self):
        self.keep_going = False
        self.listener.shutdown_event.set()
        self.listener.join()

    def main(self):

        # This loop has two jobs:
        # - process items on our workq
        # - process netlink messages on our netlinkq, messages are placed there via our NetlinkListener
        while self.keep_going:

            self.alarm.wait(60*60*24)
            self.alarm.clear()

            if self.listener.shutdown_event.is_set():
                log_verbose("NetlinkListener: shutting things down")
                break

            while not self.workq.empty():
                (event, options) = self.workq.get()

                if event == 'GET_ALL_ADDRESSES':
                    self.get_all_addresses()
                elif event == 'GET_ALL_LINKS':
                    self.get_all_links()
                elif event == 'GET_ALL_NEIGHBORS':
                    self.get_all_neighbors()
                elif event == 'GET_ALL_ROUTES':
                    self.get_all_routes()
                elif event == 'SERVICE_NETLINK_QUEUE':
                    self.service_netlinkq()
                else:
                    raise Exception("Unsupported workq event %s" % event)

        self.listener.shutdown_event.set()
        self.listener.join()

    def service_netlinkq(self):
        '''
        Handle the message on the netlink queue.
        '''
        msg_count = {}
        processed = 0

        for (msgtype, length, flags, seq, pid, data) in self.netlinkq:
            processed += 1

            # If this is a reply to a TX message that debugs were enabled for then debug the reply
            if (seq, pid) in self.debug_seq_pid:
                debug = True
            else:
                debug = self.debug_this_packet(msgtype)

            if msgtype == nlmanager.nlpacket.RTM_NEWLINK or msgtype == nlmanager.nlpacket.RTM_DELLINK:
                msg = nlmanager.nlpacket.Link(msgtype, debug)

            elif msgtype == nlmanager.nlpacket.RTM_NEWADDR or msgtype == nlmanager.nlpacket.RTM_DELADDR:
                msg = nlmanager.nlpacket.Address(msgtype, debug)

            elif msgtype == nlmanager.nlpacket.RTM_NEWNEIGH or msgtype == nlmanager.nlpacket.RTM_DELNEIGH:
                msg = nlmanager.nlpacket.Neighbor(msgtype, debug)

            elif msgtype == nlmanager.nlpacket.RTM_NEWROUTE or msgtype == nlmanager.nlpacket.RTM_DELROUTE:
                msg = nlmanager.nlpacket.Route(msgtype, debug)

            else:
                log_debug('RXed unknown netlink message type %s' % msgtype)
                continue

            msg.decode_packet(length, flags, seq, pid, data)

            if not self.filter_permit(msg):
                continue

            if debug:
                msg.dump()

            # Only used for printing debugs about how many we RXed of each type
            if msg.msgtype not in msg_count:
                msg_count[msg.msgtype] = 0
            msg_count[msg.msgtype] += 1

            # Call the appropriate handler method based on the msgtype.  The handler
            # functions are defined in our child class.
            if msg.msgtype == nlmanager.nlpacket.RTM_NEWLINK:
                self.rx_rtm_newlink(msg)

            elif msg.msgtype == nlmanager.nlpacket.RTM_DELLINK:
                self.rx_rtm_dellink(msg)

            elif msg.msgtype == nlmanager.nlpacket.RTM_NEWADDR:
                self.rx_rtm_newaddr(msg)

            elif msg.msgtype == nlmanager.nlpacket.RTM_DELADDR:
                self.rx_rtm_deladdr(msg)

            elif msg.msgtype == nlmanager.nlpacket.RTM_NEWNEIGH:
                self.rx_rtm_newneigh(msg)

            elif msg.msgtype == nlmanager.nlpacket.RTM_DELNEIGH:
                self.rx_rtm_delneigh(msg)

            elif msg.msgtype == nlmanager.nlpacket.RTM_NEWROUTE:
                self.rx_rtm_newroute(msg)

            elif msg.msgtype == nlmanager.nlpacket.RTM_DELROUTE:
                self.rx_rtm_delroute(msg)

            else:
                log_debug('RXed unknown netlink message type %s' % msgtype)

        if processed:
            self.netlinkq = self.netlinkq[processed:]

    def rx_rtm_newlink(self, msg):
        self.Intf.AddInterface(self, msg)

    def rx_rtm_dellink(self, msg):
        self.Intf.DelInterface(self, msg.ifindex, msg.family)

    def rx_rtm_newaddr(self, msg):
        global hook_server
        vlanId = Intf.GetVlanId(msg.ifindex)
        if not hook_server and vlanId == 1:
            vlan_addr = msg.get_attribute_value(msg.IFA_ADDRESS)
            log_info("vlan1 found, web hook server will use: %s" % str(vlan_addr))
            hook_server = str(vlan_addr)
            if not wh_uuid:
                WebHookInit(hook_server)

class IntfSupport():
    def __init__(self, nlm):
        self.ifInfoLock = threading.Lock()
        self.ifInfoByIndex = {}
        self.ifNameToIndex = {}
        self.peerlink = None

        # Dump the interface table and load up the ifInfoByIndex database
        debug = nlmanager.nlpacket.RTM_GETLINK in nlm.debug
        for msg in nlm.request_dump(nlmanager.nlpacket.RTM_GETLINK, socket.AF_UNSPEC, debug):
            self.AddInterface(nlm, msg)
        for msg in nlm.request_dump(nlmanager.nlpacket.RTM_GETLINK, socket.AF_BRIDGE, debug):
            self.AddInterface(nlm, msg)

    def CombineDicts(self, dest, source):
        for k,v in source.iteritems():
            if v is not None:
                if isinstance(v, dict):
                    self.CombineDicts(dest.setdefault(k,{}), v)
                else:
                    dest[k] = v

    def AddInterface(self, nlm, msg):
        self.ifInfoLock.acquire()
        ifDict = self.ifInfoByIndex.setdefault(msg.ifindex, {})
        srcLinkInfo = msg.get_attribute_value(msg.IFLA_LINKINFO, {})
        kind = srcLinkInfo.get(msg.IFLA_INFO_KIND)
        srcLinkData = srcLinkInfo.get(msg.IFLA_INFO_DATA, {})
        linkData = {}
        if kind == 'vlan':
            linkData = {msg.IFLA_VLAN_ID: srcLinkData.get(msg.IFLA_VLAN_ID)}
        elif kind == 'vxlan':
            linkData = {msg.IFLA_VXLAN_ID: srcLinkData.get(msg.IFLA_VXLAN_ID)}
        linkInfo = {
            msg.IFLA_INFO_KIND : kind,
            msg.IFLA_INFO_DATA : linkData
        }
        srcProtInfo = msg.get_attribute_value(msg.IFLA_PROTINFO, {})
        protInfo = {
            msg.IFLA_BRPORT_PEER_LINK : srcProtInfo.get(msg.IFLA_BRPORT_PEER_LINK),
        }
        nlDict = {
            msg.IFLA_IFNAME     : msg.get_attribute_value(msg.IFLA_IFNAME),
            msg.IFLA_MASTER     : msg.get_attribute_value(msg.IFLA_MASTER),
            msg.IFLA_LINK       : msg.get_attribute_value(msg.IFLA_LINK),
            msg.IFLA_LINKINFO   : linkInfo,
            msg.IFLA_PROTINFO   : protInfo
        }
        self.CombineDicts(ifDict, nlDict)
        name = ifDict.get(nlmanager.nlpacket.Link.IFLA_IFNAME)
        if name:
            self.ifNameToIndex[name] = msg.ifindex
        self.ifInfoLock.release()

    def DelInterface(self, nlm, idx, family):
        self.ifInfoLock.acquire()
        ifDict = self.ifInfoByIndex.get(idx, {})
        name = ifDict.get(nlmanager.nlpacket.Link.IFLA_IFNAME)
        if family == socket.AF_BRIDGE:
            ifDict.pop(nlmanager.nlpacket.Link.IFLA_PROTINFO, None)
            ifDict.pop(nlmanager.nlpacket.Link.IFLA_AF_SPEC, None)
            self.ifInfoLock.release()
        else:
            self.ifInfoByIndex.pop(idx, None)
            self.ifNameToIndex.pop(name, None)
            self.ifInfoLock.release()

    def GetIfIndex(self, nlm, ifName):
        self.ifInfoLock.acquire()
        idx = self.ifNameToIndex.get(ifName)
        self.ifInfoLock.release()
        if not idx:
            idx = nlm.get_iface_index(ifName)
        return idx

    def GetMasterBond(self, iface, expected=False):
        bond = None
        self.ifInfoLock.acquire()
        idx = self.ifNameToIndex.get(iface)
        master = self.ifInfoByIndex.get(idx, {}).get(nlmanager.nlpacket.Link.IFLA_MASTER)
        info = self.ifInfoByIndex.get(master, {}).get(nlmanager.nlpacket.Link.IFLA_LINKINFO, {})
        if info.get(nlmanager.nlpacket.Link.IFLA_INFO_KIND) == "bond":
            bond = self.ifInfoByIndex.get(master, {}).get(nlmanager.nlpacket.Link.IFLA_IFNAME)
        self.ifInfoLock.release()
        if expected and not bond:
            try:
                iface_info = subprocess.check_output(["ip", "link", "show", "dev", iface]).split()
                bond = iface_info[iface_info.index("master") + 1]
            except:
                pass
        return bond

    def GetBridge(self):
        # VLAN Aware only
        self.ifInfoLock.acquire()
        brName = None
        for ifDict in self.ifInfoByIndex.itervalues():
            info = ifDict.get(nlmanager.nlpacket.Link.IFLA_LINKINFO, {})
            if info.get(nlmanager.nlpacket.Link.IFLA_INFO_KIND) == "bridge":
                brName = ifDict.get(nlmanager.nlpacket.Link.IFLA_IFNAME)
                break
        self.ifInfoLock.release()
        return brName

    def GetPeerlink(self):
        self.ifInfoLock.acquire()
        for ifDict in self.ifInfoByIndex.itervalues():
            protinfo = ifDict.get(nlmanager.nlpacket.Link.IFLA_PROTINFO, {})
            peerlink = protinfo.get(nlmanager.nlpacket.Link.IFLA_BRPORT_PEER_LINK, False)
            if peerlink:
                self.peerlink = ifDict.get(nlmanager.nlpacket.Link.IFLA_IFNAME)
                break
        self.ifInfoLock.release()
        return self.peerlink

    def GetVlanId(self, idx):
        self.ifInfoLock.acquire()
        vlanId = None
        info = self.ifInfoByIndex.get(idx, {}).get(nlmanager.nlpacket.Link.IFLA_LINKINFO, {})
        if info.get(nlmanager.nlpacket.Link.IFLA_INFO_KIND) == "vlan":
            data = info.get(nlmanager.nlpacket.Link.IFLA_INFO_DATA, {})
            vlanId = data.get(nlmanager.nlpacket.Link.IFLA_VLAN_ID)
        self.ifInfoLock.release()
        return vlanId

    def GetVxlanIface(self, vxlanId):
        self.ifInfoLock.acquire()
        ifName = None
        for ifDict in self.ifInfoByIndex.itervalues():
            info = ifDict.get(nlmanager.nlpacket.Link.IFLA_LINKINFO, {})
            if info.get(nlmanager.nlpacket.Link.IFLA_INFO_KIND) == "vxlan":
                data = info.get(nlmanager.nlpacket.Link.IFLA_INFO_DATA, {})
                vni = data.get(nlmanager.nlpacket.Link.IFLA_VXLAN_ID)
                if vxlanId == vni:
                    ifName = ifDict.get(nlmanager.nlpacket.Link.IFLA_IFNAME)
                    break
        self.ifInfoLock.release()
        return ifName


class WebHookHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    """
    This class overrides the BaseHTTPServer's request handler members to handle
    certain types of HTTP requests.
    """
    def _set_headers(self):
        self.send_response(200, 'OK')
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        log_debug("*** POST Headers:")
        log_debug(pp.pformat(str(self.headers)))
        log_debug("*** POST Data:")
        post_json = json.loads(post_data)
        log_debug(pp.pformat(post_json))
        if post_json['event_type'] == "VM.ON":
            wq.put("vm-add", post_json.get('data', {}).get('metadata', {}))
        elif post_json['event_type'] == "VM.OFF":
            wq.put("vm-del", post_json.get('data', {}).get('metadata', {}).get('metadata', {}).get('uuid', None))
        elif post_json['event_type'] == "VM.MIGRATE":
            wq.put("vm-move", post_json.get('data', {}).get('metadata', {}))
        self._set_headers()

class HostsClass():
    """
    A class to support manipulation of NTX hosts
    """
    def __init__(self, rest_api, api_library):
        self.rest_api = rest_api
        self.api_library = api_library

    def get_host(self, uuid):
        log_debug("Getting host with UUID %s" % (uuid,))
        if not ipmi_bypass:
            (status, result) = self.rest_api.rest_call(sub_url="hosts/%s" % (uuid,),
                                                       method="GET")
            if str(status) != "200":
                self.api_library.print_failure(result, "Failed to get host with UUID %s" % (uuid,))
                return {}
        else:
            # To workaround the bug when ipmi unconfigured and requesting a host
            # with v3 rest api, we need to use rest api v2
            (status, result) = self.rest_api.rest_call(sub_url="hosts/%s" % (uuid,),
                                                       version=2, method="GET")
            if str(status) != "200":
                self.api_library.print_failure(result, "Failed to get host with UUID %s (v2)" % (uuid,))
                return {}
            result = {'status': { 'name': result.get('name', None)}}
        return result

class SubnetClass():
    """
    A class to support manipulation of subnets
    """
    def __init__(self, rest_api, api_library):
        self.rest_api = rest_api
        self.api_library = api_library

    def get_subnet(self, uuid):
        log_debug("Getting subnet with UUID %s" % (uuid,))
        (status, result) = self.rest_api.rest_call(sub_url="subnets/%s" % (uuid,),
                                                   method="GET")
        if str(status) != "200":
            self.api_library.print_failure(result, "Failed to get subnet with UUID %s" % (uuid,))
            return {}
        return result

class VmsClass():
    """
    A class to support manipulation of VMs
    """
    def __init__(self, rest_api, api_library):
        self.rest_api = rest_api
        self.api_library = api_library

    def get_running_vms(self):
        body = {
            "kind" : "vm",
            "length" : 100,
            "offset" : 0,
            "filter": "power_state==on"
        }
        (status, result) = self.rest_api.rest_call(sub_url="vms/list",
                                                   method="POST", body=body)
        log_debug("get_vm_list status: " + str(status))
        log_debug("    Here is the result:\n" + pp.pformat(result))

        if str(status) != "200":
            self.api_library.print_failure(result, "Failed to get list of active VMs")
            return {}
        return result

class WebHookClass():
    """
    A class to support manipulation of web hooks
    """
    def __init__(self, rest_api, api_library, hook_server, hook_port):
        self.rest_api = rest_api
        self.api_library = api_library
        self.hook_server = hook_server
        self.hook_port = hook_port
        self.post_url = "http://%s:%d/hooks" % (hook_server, hook_port)
        self.wh_deleted = False

    def get_web_hooks(self):
        body = {
            "kind" : "webhook",
            "length" : 100,
            "offset" : 0,
        }
        (status, result) = self.rest_api.rest_call(sub_url="webhooks/list",
                                                   method="POST", body=body)
        log_debug("get_web_hooks status: " + str(status))
        log_debug("    Here is the result:\n" + pp.pformat(result))

        if str(status) != "200":
            self.api_library.print_failure(result, "Failed to get list of webhooks")
            return None

        return result

    def del_web_hook(self, uuid):
        log_debug("Removing webhook with UUID %s" % (uuid,))
        (status, result) = self.rest_api.rest_call(sub_url="webhooks/%s" % (uuid,),
                                                   method="DELETE" )
        if str(status) != "202":
            self.api_library.print_failure(result, "Failed to remove webhook with UUID %s" % (uuid,))
            return True

        return False

    def del_all_web_hooks(self):
        result = self.get_web_hooks()
        if result is None:
            self.wh_deleted = True
            return True

        for webhook in result.get('entities', []):
            post_url = webhook.get('spec', {}).get('resources', {}).get('post_url')
            if post_url == self.post_url:
                uuid = webhook.get('metadata', {}).get('uuid')
                if uuid is not None:
                    if self.del_web_hook(uuid):
                        self.wh_deleted = True
                        return True

        return False

    def add_web_hook(self, descr="Webhook", filters=["VM.ON", "VM.OFF", "VM.MIGRATE"], name="wh1"):
        body = {
            "spec" : {
                "description" : descr,
                "resources" : {
                    "post_url" : self.post_url,
                    "events_filter_list": filters,
                },
                "name": name
            },
            "api_version": "3.0",
            "metadata": {
                "kind": "webhook"
            }
        }
        status, result = self.rest_api.rest_call(sub_url="webhooks",
                                                 method="POST", body=body)
        if str(status) != "202":
            self.api_library.print_failure(result, "Failed to add webhook with name %s" % (name,))
            return None

        log_debug("Added web hook:\n" + pp.pformat(result))
        return result.get("metadata", {}).get("uuid")


class NtnxRestApi():
    """
    A REST API used for interfacing to Nutanix CVMs.
    """
    def __init__(self, ip_addr, username, password, port=9440):
        # Initialise the options.
        self.ip_addr = ip_addr
        self.username = username
        self.password = password
        self.port = port

    # Create a REST client session.
    def rest_call(self, sub_url="", method="", body=None, version=3,
                  content_type="application/json"):
        if version == 3:
            base_url = 'https://%s:%d/api/nutanix/v%d/%s' % (self.ip_addr, self.port,
                                                             version, sub_url)
        elif version == 2:
            base_url = 'https://%s:%d/PrismGateway/services/rest/v2.0/%s' % (self.ip_addr,
                                                                             self.port, sub_url)
        if body and content_type == "application/json":
            body = json.dumps(body)
        request = urllib2.Request(base_url, data=body)
        base64string = base64.encodestring(
            '%s:%s' %
            (self.username, self.password)).replace(
            '\n', '')
        request.add_header("Authorization", "Basic %s" % base64string)

        request.add_header(
            'Content-Type',
            '%s; charset=utf-8' %
            content_type)
        request.get_method = lambda: method

        try:
            if sys.version_info >= (2, 7, 9):
                ssl_context = ssl._create_unverified_context()
                response = urllib2.urlopen(request, context=ssl_context)
            else:
                response = urllib2.urlopen(request)
            result = response.read()
            if result:
                result = json.loads(result)
            return response.code, result
        except urllib2.HTTPError as e:
            err_result = e.read()
            if err_result:
                try:
                    err_result = json.loads(err_result)
                except:
                    log_error("Error: %s" % e)
                    return "408", None
            return "408", err_result
        except Exception as e:
            log_error("Error: %s" % e)
            return "408", None


class NtnxApiLibrary:
    """
    """
    def __init__(self):
        pass

    # Parse a list
    # list to parse
    # key for which parse is to be done
    def parse_list(self, toparse, lookfor):
        for data in toparse:
            if isinstance(data, dict):
                return data.get(lookfor)

    # Parse a complex dictionary.
    # result : dictionary to parse
    # meta_key : the key which has sub key for which parse is being done.
    # look_for: the key for which parse is to be done.
    def parse_result(self, result, meta_key, lookfor):
        uuid = None
        if result:
            for key in result:
                if key == meta_key:
                    if isinstance(result[key], list):
                        uuid = self.parse_list(result[key], lookfor)
                        return uuid
                    else:
                        if type(result[key]) == dict:
                            return result[key].get(lookfor, None)
                        return result[key]
                elif isinstance(result[key], dict):
                    uuid = self.parse_result(result[key], meta_key, lookfor)
                    if uuid:
                        return uuid
        return uuid

    # Check the return status of API executed
    def check_api_status(self, status, result):
        if result:
            return self.parse_result(result, "status", "state")
        else:
            return None

    def print_failure_status(self, result):
        if result:
            status = result.get('status')
            if status:
                print '*' * 80
                state = self.parse_result(result, "status", "state")
                if state == "kError":
                    print "Reason: ", status.get('reason')
                    print "Message: ", status.get("message")
                else:
                    print "Reason: ", result.get('reason')
                    print "Details: ", result.get('details')
                    print "Message: ", result.get("message")
                print '*' * 80

    def print_failure(self, result, message):
        print message
        self.print_failure_status(result)

    def __is_result_complete(self, status, result):
        if result and str(result.get('code')) == "404":
            return True
        if result and str(status) == "200":
            api_status = self.parse_result(result, "status", "state")
            if api_status == "kComplete":
                return True
            elif api_status == "kError":
                return None
        return False

    def track_completion_status(
            self, rest_api, status, result, get_api_status):
        retry_count = 5
        wait_time = 2  # seconds
        uuid = None

        if result and str(status) == "200":
            uuid = self.parse_result(result, "metadata", "uuid")

        if self.__is_result_complete(status, result):
            return uuid
        else:
            api_status = self.parse_result(result, "status", "state")
            if uuid and api_status != "kComplete" and api_status != "kError":
                count = 0
                while count < retry_count:
                    count = count + 1
                    time.sleep(wait_time)
                    (status, result) = get_api_status(rest_api, uuid)
                    get_status = self.__is_result_complete(status, result)
                    # API status is kComplete
                    if get_status is True:
                        return uuid
                    # API status is Error
                    if get_status is None:
                        break

            self.print_failure_status(result)
            api_status = self.parse_result(result, "status", "state")
            print "API status :", api_status
            return None


    def track_deletion_status(self, rest_api, uuid, get_api_status):
        count = 0
        api_status = ""
        status = 0
        result = None
        while count < 3:
            count = count + 1
            time.sleep(5)
            (status, result) = get_api_status(rest_api, uuid)
            if result:
                if str(status) == "200":
                    api_status = self.parse_result(result, "status", "state")
                else:
                    api_status = result.get('status', None)
            if api_status == "failure":
                return True
        if not str(status) == "200":
            self.print_failure_status(result)
            return False
        else:
            if api_status == "kComplete":
                return True
            elif api_status == "failure":
                self.print_failure_status(result)
                return False
            elif api_status == "kError":
                print "Reason:", self.parse_result(result, "status", "reason")
                print "Message:", self.parse_result(result, "status", "message")
                return False
            else:
                print "Timed Out"
                print result
                return False


class HttpServer:
    def __init__(self, server="", port=hook_port, handler=WebHookHandler):
        self.httpd = BaseHTTPServer.HTTPServer((server, port), handler)

        self.httpd_thread = threading.Thread(None, self.httpd.serve_forever, "httpd_thread")
        self.httpd_thread.daemon = True
        self.httpd_thread.start()

    def stop(self):
        self.httpd.shutdown()
        if threading.current_thread().name != "http_thread":
            self.httpd_thread.join()


class PeriodicSync:
    def __init__(self):
        self.keep_going = True
        self.sync_event = threading.Event()
        self.periodic_dump_thread = threading.Thread(None, self.periodic_dump_t, "periodic_dump_thread")
        self.periodic_dump_thread.daemon = True
        self.periodic_dump_thread.start()

    def stop(self):
        self.keep_going = False
        self.sync_event.set()
        if threading.current_thread().name != "periodic_dump_thread":
            self.periodic_dump_thread.join()

    def periodic_dump_t(self):
        try:
            self.periodic_dump()
        except Exception:
            dump_traceback()
            stop_processing(3, 1)

    def periodic_dump(self):
        log_debug("Beginning execution of the thread periodic_dump")
        while not self.sync_event.wait(periodic_sync_timeout) and self.keep_going:
            if hook_server and not wh_uuid:
                WebHookInit(hook_server)
            log_debug("Periodic VM dump")
            vmDBLock.acquire()
            vmDelDB = vmDB.copy()
            vmDBLock.release()
            elements = vms.get_running_vms() if wh_uuid else {}
            for element in elements.get('entities', {}):
                vm_uuid = element.get('metadata', {}).get('uuid', None)
                if vm_uuid not in vmDelDB:
                    wq.put("vm-add", element)
                else:
                    host_ref = element.get('status', {}).get('resources', {}).get('host_reference', {})
                    host_id = host_ref.get('uuid', None) if host_ref.get('kind',"") == "host" else None
                    if host_id:
                        host = hosts.get_host(host_id)
                        host_name = host.get('status', {}).get('name', None)
                        bond_name = GetBondBasedOnHost(host_name)
                        if host_name != vmDelDB[vm_uuid][2] and bond_name != vmDelDB[vm_uuid][0]:
                            wq.put("vm-move", element)
                    del vmDelDB[vm_uuid]
            if elements:
                for vm in vmDelDB:
                    wq.put("vm-del", vm)

            log_debug("Periodic clag-id check")
            autobondsLock.acquire()
            bonds = autobonds.copy()
            autobondsLock.release()
            try:
                ClagCmd = clag.clagdcmd.clagdcmd()
                clagBonds = json.loads(ClagCmd.run("GetClagIntfDB"))
            except:
                ClagCmd = None

            for bond, (bond_added, clag_id, [iface], bridge, neigh_name) in bonds.iteritems():
                try:
                    if clag_id != clagBonds[bond]['clagId']:
                        clag.clagdcmd.clagdcmd().run(" ".join(["setclagid", str(bond), clag_id]))
                except:
                    log_error("Error setting clagid %s for %s" % (clag_id, bond))
            if ClagCmd:
                ClagCmd.close()


class LldpMonitor:
    """
    """
    def __init__(self):
        self.keep_going = True
        self.lldp_sub_process = None
        self.lldp_thread = threading.Thread(None, self.monitor_lldp_thread, "lldp_thread")
        self.lldp_thread.daemon = True
        self.lldp_thread.start()

    def stop(self):
        self.keep_going = False
        if self.lldp_sub_process is not None:
            self.lldp_sub_process.terminate()
        if threading.current_thread().name != "lldp_thread":
            self.lldp_thread.join()

    def monitor_lldp_thread(self):
        try:
            self.monitor_lldp()
        except Exception:
            dump_traceback()
            stop_processing(3, 1)

    def monitor_lldp(self):
        log_debug("Beginning execution of the thread monitor_lldp")
        time.sleep(5)
        while self.keep_going:
            lldp_json_str = ''
            while self.keep_going and self.lldp_sub_process is None:
                try:
                    log_debug("Opening lldp_sub_process")
                    self.lldp_sub_process = subprocess.Popen(['/usr/sbin/lldpcli', '-f', 'json', 'watch'],
                                                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                except OSError:
                    log_error("Unable to execute the '/usr/sbin/lldpcli -f json watch' command.")
                    time.sleep(10)

            # Get the current LLDP neighbors, just to kick things off.
            try:
                lldp_str = subprocess.check_output(["/usr/sbin/lldpcli", "-f", "json", "show", "neighbors"])
            except subprocess.CalledProcessError as e:
                log_error("Error getting lldp table (lldpcli -f json show neighbors). %s" % (e,))
                lldp_str = ""
            try:
                lldp_element = json.loads(lldp_str.strip())['lldp'][0]['interface']
            except:
                lldp_element = {}
            for lldp_data in lldp_element:
                log_debug("Adding entry to the work queue: %s" % (pp.pformat(lldp_data),))
                wq.put("lldp-add", lldp_data)

            # Now use the watch command to see all LLDP modifications
            for lldp_str in iter(self.lldp_sub_process.stdout.readline, b''):
                if not self.keep_going:
                    break
                lldp_json_str += lldp_str
                if not lldp_str.strip():
                    lldp_data = json.loads(lldp_json_str)
                    if 'lldp-added' in lldp_data:
                        log_debug("Adding entry to the work queue: %s" % (pp.pformat(lldp_data),))
                        lldp_data = lldp_data['lldp-added'][0]['interface'][0]
                        wq.put("lldp-add", lldp_data)
                    elif 'lldp-deleted' in lldp_data:
                        log_debug("Adding entry to the work queue: %s" % (pp.pformat(lldp_data),))
                        lldp_data = lldp_data['lldp-deleted'][0]['interface'][0]
                        wq.put("lldp-del", lldp_data)
                    lldp_json_str = ''

        log_debug("Finished execution of the thread monitor_lldp")


class WorkQueue:
    def __init__(self):
        self.keep_going = True
        self.work_queue = Queue.Queue()
        self.work_queue_thread = threading.Thread(None, self.work_queue_t, "work_queue_thread")
        self.work_queue_thread.daemon = True
        self.work_queue_thread.start()

    def stop(self):
        # Drain the queue
        self.keep_going = False
        while not self.work_queue.empty():
            try:
                self.work_queue.get(False)
            except Queue.Empty:
                continue
        self.put('stop', None)
        if threading.current_thread().name != "work_queue_thread":
            self.work_queue_thread.join()

    def put(self, opcode, param):
        if opcode in ['vm-add', 'vm-del', 'vm-move', 'lldp-add', 'lldp-del', 'stop']:
            #print "Adding to work queue for op %s : %s" % (opcode, pp.pformat(param[0]))
            self.work_queue.put((opcode, param))
        else:
            log_error("Unknown opcode added to work queue: %s" (opcode,))

    def work_queue_t(self):
        try:
            self.monitor_work_queue()
        except Exception:
            dump_traceback()
            stop_processing(3, 1)

    def monitor_work_queue(self):
        log_debug("Beginning execution of the thread monitor_work_queue")
        nlm = nlmanager.nlmanager.NetlinkManager(_NLM_WORKQ)
        lldpDB = []
        while self.keep_going:
            (opcode, element) = self.work_queue.get()
            log_debug("Processing the op code %s from the work queue" % (opcode,))
            if opcode == "stop" or not self.keep_going:
                break
            if opcode in ["vm-add", "vm-move"]:
                vm_uuid = element.get('metadata', {}).get('uuid', None)
                vm_name = element.get('spec', {}).get('name', None)
                subnet_id = element.get('spec', {}).get('resources', {}).get('nic_list', [{}])[0].get('subnet_reference', {}).get('uuid', None)
                mac = element.get('spec', {}).get('resources', {}).get('nic_list', [{}])[0].get('mac_address', None)
                subnet = subnets.get_subnet(subnet_id)
                vlanId = subnet.get('status', {}).get('resources', {}).get('vlan_id', None)
                host_ref = element.get('status', {}).get('resources', {}).get('host_reference', {})
                if host_ref.get('kind',"") == "host":
                    host_id = host_ref.get('uuid', None)
                    host = hosts.get_host(host_id)
                    host_name = host.get('status', {}).get('name', None)
                    log_verbose("Host is: %s" % host_name)
                    bond_name = GetBondBasedOnHost(host_name)
                    if opcode == "vm-add":
                        if vm_uuid not in vmDB:
                            vmDB[vm_uuid] = [bond_name, vlanId, host_name, vm_name, mac]
                            log_info("VM %s added" % vm_name)
                            if bond_name:
                                vlanDBLock.acquire()
                                AddVlanConfig(nlm, bond_name, vlanId)
                                vlanDBLock.release()
                                AddStaticMac(nlm, mac, bond_name, vlanId)
                            else:
                                log_verbose("No bond connected to host %s" % str(host_name))
                    else:
                        vmDBLock.acquire()
                        log_info("VM %s moved" % vm_name)
                        vm = vmDB.get(vm_uuid, [])
                        if vm and vm[0] != bond_name:
                            if vm[0]:
                                DelStaticMac(nlm, vm[4], vm[0], vm[1])
                                vlanDBLock.acquire()
                                DelVlanConfig(nlm, vm[0], vm[1])
                                vlanDBLock.release()
                            vmDB[vm_uuid] = [bond_name, vlanId, host_name, vm_name, mac]
                            if bond_name:
                                vlanDBLock.acquire()
                                AddVlanConfig(nlm, bond_name, vlanId)
                                vlanDBLock.release()
                                AddStaticMac(nlm, mac, bond_name, vlanId)
                            else:
                                log_verbose("No bond connected to host %s" % str(host_name))
                        vmDBLock.release()

            elif opcode == "vm-del":
                vmDBLock.acquire()
                vm = vmDB.get(element, [])
                if vm:
                    log_info("VM %s deleted" % vm[3])
                    if vm[0]:
                        DelStaticMac(nlm, vm[4], vm[0], vm[1])
                        vlanDBLock.acquire()
                        DelVlanConfig(nlm, vm[0], vm[1])
                        vlanDBLock.release()
                    del vmDB[element]
                vmDBLock.release()

            if opcode in ["lldp-add", "lldp-del"]:
                try:
                    lldp_neigh = element.get('chassis', [{}])[0].get('descr', [{}])[0].get('value', [])
                except:
                    continue
                if 'NutanixAHV' in lldp_neigh or 'CentOS' in lldp_neigh and 'nutanix' in lldp_neigh:
                    lldp_iface = element.get('name')
                    neigh_mac = element.get('chassis', [{}])[0].get('id', [{}])[0].get('value', None)
                    neigh_name = element.get('chassis', [{}])[0].get('name', [{}])[0].get('value', None)
                    if not neigh_name or not neigh_mac:
                        continue
                    clag_id = str(crc16(str.encode(str(neigh_mac))))
                    if opcode == "lldp-add":
                        if neigh_name in lldpDB:
                            continue
                        lldpDB.append(neigh_name)
                        autobondsLock.acquire()
                        CreateClagBond(nlm, lldp_iface, clag_id, neigh_name)
                        autobondsLock.release()
                        vmDBLock.acquire()
                        AddVlanConfigNeighAdd(nlm, lldp_iface, neigh_name)
                        vmDBLock.release()
                    else:
                        global lldp_del_ignore
                        if neigh_name not in lldpDB:
                            continue
                        elif lldp_iface in lldp_del_ignore:
                            lldp_del_ignore.remove(lldp_iface)
                            continue
                        lldpDB.remove(neigh_name)
                        vmDBLock.acquire()
                        DelVlanConfigNeighDel(nlm, lldp_iface, neigh_name)
                        vmDBLock.release()
                        autobondsLock.acquire()
                        DeleteClagBond(nlm, lldp_iface)
                        autobondsLock.release()
        log_debug("Finished execution of the thread monitor_work_queue")


def signal_handler(signum, frame):
    if signum == signal.SIGTERM:
        stop_processing(3, 0)
    else:
        stop_processing(3, 1)

def dump_traceback():
    (exc_type, exc_value, exc_traceback) = sys.exc_info()
    err = "".join(traceback.format_exception(exc_type, exc_value, exc_traceback))
    if logger:
        log_error("unhandled exception:")
        for line in err.split('\n'):
            log_error("    %s" % (line,))
    else:
        print "unhandled exception:"
        for line in err.split('\n'):
            print "    %s" % (line,)

def read_config():
    global username
    global password
    global server
    global hook_server
    global hook_port
    global socket_timeout
    global vxlan_config
    global vxlan_local_ip
    global loglevel
    global periodic_sync_timeout
    global ipmi_bypass
    with open('/etc/default/cumulus-hyperconverged') as f:
        for line in f:
            line = line.strip()
            split = line.strip().split('=')
            if len(split) <= 1:
                continue
            key = split[0]
            value = split[1]
            if key == "USERNAME":
                username = value
            elif key == "PASSWORD":
                password = value
            elif key == "SERVER":
                server = value
            elif key == "HOOK_SERVER":
                hook_server = value
            elif key == "HOOK_PORT":
                hook_port = value
            elif key == "SOCKET_TIMEOUT":
                socket_timeout = value
            elif key == "VXLAN_CONFIG":
                vxlan_config = False if value.lower() in ('no', 'false', 'f', 'n', '0') else True
            elif key == "VXLAN_LOCAL_IP":
                vxlan_local_ip = value
            elif key == "LOGLEVEL":
                loglevel = value
            elif key == "PERIODIC_SYNC_TIMEOUT":
                try:
                    periodic_sync_timeout = int(value)
                except ValueError:
                    periodic_sync_timeout = 60
            elif key == "IPMI_BYPASS":
                ipmi_bypass = True if value.lower() in ('yes', 'true', 't', 'y', '1') else False

def init_logging():
    '''
    Set up the logging according to the value in the config file.
    '''
    facility = logging.handlers.SysLogHandler.LOG_DAEMON
    handler = logging.handlers.SysLogHandler(address="/dev/log", facility=facility)
    formatter = logging.Formatter("cumulus-hyperconverged[%(process)d]: %(message)s", None)
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    if loglevel == "debug":
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

def log_info(message):
    """
    Always output the message
    """
    logger.info(message)

def log_error(message):
    """
    Always output the error message
    """
    logger.error(message)

def log_verbose(message):
    """
    Output the message if verbose output is enabled
    """
    if loglevel in ["verbose", "debug"]:
        logger.info(message)

def log_debug(message):
    """
    Output the message if debug output is enabled
    """
    if loglevel == "debug":
        logger.debug(message)

def crc16(data, poly=0x8408):
    data = bytearray(data)
    crc = 0xFFFF
    for b in data:
        cur_byte = 0xFF & b
        for _ in range(0, 8):
            if (crc & 0x0001) ^ (cur_byte & 0x0001):
                crc = (crc >> 1) ^ poly
            else:
                crc >>= 1
            cur_byte >>= 1
    crc = (~crc & 0xFFFF)
    crc = (crc << 8) | ((crc >> 8) & 0xFF)
    return crc & 0xFFFF

def WebHookInit(hook_server):
    global wh
    global wh_uuid
    global http_server
    wh = WebHookClass(ntnx_rest_api, api_library, hook_server, hook_port)
    # Remove all web hooks that may currently be registered by us
    if not wh.wh_deleted:
        wh.del_all_web_hooks()
    # Register for the webhooks
    if not wh_uuid:
        if not http_server:
            http_server = HttpServer(port=hook_port)
        wh_uuid = wh.add_web_hook()

def GetBondBasedOnHost(host_name):
    bond_name = None
    autobondsLock.acquire()
    for key, value in autobonds.copy().iteritems():
        if host_name == value[4]:
            bond_name = key
    autobondsLock.release()
    return bond_name

def EnableLacpBypass(bond):
    try:
        with open("/sys/class/net/%s/bonding/lacp_bypass" % (bond,), "w") as f:
            f.write("1")
    except IOError:
        log_error("Error enabling LACP bypass on %s" % (bond,))

def CreateClagBond(nlm, iface, clag_id, neigh_name):
    autobond = "bond_" + iface
    bond = Intf.GetMasterBond(iface)
    if bond in autobonds or autobond in autobonds:
        return
    bond_added = False
    if bond:
        try:
            subprocess.check_call(["/usr/bin/clagctl", "setclagid", bond, clag_id])
            log_info("Setting clag_id for bond %s to %s" % (bond, clag_id))
        except subprocess.CalledProcessError as e:
            log_error("Error setting clagid %s" % (e,))
    else:
        try:
            bond = autobond
            subprocess.check_call(["ip", "link", "add", bond, "type", "bond"])
            EnableLacpBypass(bond)
            global lldp_del_ignore
            lldp_del_ignore.append(iface)
            nlm.link_set_updown(iface, "down")
            time.sleep(1)
            subprocess.check_call(["ip", "link", "set", iface, "master", bond])
            nlm.link_set_updown(iface, "up")
            nlm.link_set_updown(bond, "up")
            subprocess.check_call(["/usr/bin/clagctl", "setclagid", bond, clag_id])
            log_info("Automatically added bond %s with clag_id %s" % (bond, clag_id))
            bond_added = True
        except subprocess.CalledProcessError as e:
            log_error("Error creating bond and setting clagid %s" % (e,))

    #TODO: need to add to br ports with correct attributes
    bridge = Intf.GetBridge()
    bridge_idx = Intf.GetIfIndex(nlm, bridge)
    if bridge:
        nlm.link_set_master(bond, master_ifindex=bridge_idx)
    autobonds[bond] = ( bond_added, clag_id, [iface], bridge, neigh_name )

def DeleteClagBond(nlm, iface):
    bond = Intf.GetMasterBond(iface)
    if bond and bond in autobonds:
        try:
            subprocess.check_call(["/usr/bin/clagctl", "setclagid", bond, "0"])
            log_info("Removing clag id from bond %s" % (bond,))
            if autobonds.get(bond, (False, 0, [], "", ""))[0]:
                nlm.link_del(ifname=bond)
                nlm.link_set_updown(iface, "up")
                log_info("Removing automatically added bond %s" % (bond,))
            if bond in autobonds:
                del autobonds[bond]
        except subprocess.CalledProcessError as e:
            log_error("Error deleting bond %s" % (e,))

def IsVlanConfiguredOnIface(nlm, iface, vlanId):
    ifaceDict = {}
    ifaceDict = nlm.vlan_get(filter_vlanid=(vlanId,))
    if iface in ifaceDict:
        return True
    return False

def SetBridgeLearningOff(nlm, iface):
    protinfo = {
        nlmanager.nlpacket.Link.IFLA_BRPORT_LEARNING : 0
    }
    debug = nlmanager.nlpacket.RTM_SETLINK in nlm.debug
    idx = Intf.GetIfIndex(nlm, iface)
    link = nlmanager.nlpacket.Link(nlmanager.nlpacket.RTM_SETLINK, debug)
    link.flags = nlmanager.nlpacket.NLM_F_REQUEST
    link.family = socket.AF_BRIDGE
    link.body = struct.pack('=BxxxiLL', socket.AF_BRIDGE, idx, 0, 0)
    link.add_attribute(nlmanager.nlpacket.Link.IFLA_PROTINFO | nlmanager.nlpacket.NLA_F_NESTED, protinfo)
    link.build_message(nlm.sequence.next(), nlm.pid)
    return nlm.tx_nlpacket_raw(link.message)

def MstpVxlanConfig(bridge, vx_dev):
    mstp_cmd = {'setportpathcost': '0', 'setportautoedge': 'yes', 'setportadminedge': 'yes',
                'setportbpdufilter': 'yes', 'setportp2p': 'auto', 'setbpduguard': 'yes'}
    try:
        for mstp_param, mstp_value in mstp_cmd.iteritems():
            subprocess.check_call(["/sbin/mstpctl", mstp_param, bridge, vx_dev, mstp_value])
        subprocess.check_call(["/sbin/mstpctl", 'settreeportprio', bridge, vx_dev, '0', '128'])
    except:
        log_error("STP configuration for %s failed" % vx_dev)

def AddVlanConfigNeighAdd(nlm, iface, neighbor):
    bond = Intf.GetMasterBond(iface, True)
    for vm, value in vmDB.copy().iteritems():
        if neighbor == value[2]:
            vmDB[vm][0] = bond
            vlanDBLock.acquire()
            AddVlanConfig(nlm, bond, value[1])
            vlanDBLock.release()
            AddStaticMac(nlm, value[4], bond, value[1])

def DelVlanConfigNeighDel(nlm, iface, neighbor):
    for vm, value in vmDB.copy().iteritems():
        if neighbor == value[2]:
            DelStaticMac(nlm, value[4], value[0], value[1])
            vlanDBLock.acquire()
            DelVlanConfig(nlm, value[0], value[1])
            vlanDBLock.release()
            vmDB[vm][0] = None

def AddVlanConfig(nlm, bond, vlanId):
    if not vlanId:
        return
    bond_idx = Intf.GetIfIndex(nlm, bond)
    bridge = Intf.GetBridge()
    bridge_idx = Intf.GetIfIndex(nlm, bridge)
    vx_dev = "vx-"+ str(vlanId)
    vlan = vlanDB.get(vlanId, (0, {}, False, False, False))
    if vlan[0] >= 1:
        #log_debug("Vlan %s and vx-%s already configured" % (vlanId, vx_dev))
        if bond not in vlan[1]:
            if IsVlanConfiguredOnIface(nlm, bond, vlanId):
                vlanDB[vlanId][1][bond] = [0, True]
            else:
                log_verbose("Adding vlan %d to %s" % (vlanId, bond))
                nlm.vlan_modify(nlmanager.nlpacket.RTM_SETLINK, bond_idx, vlanId, bridge_master=bridge_idx)
                vlanDB[vlanId][1][bond] = [0, False]
        vlanDB[vlanId][1][bond][0] += 1
        vlanDB[vlanId][0] += 1
        log_verbose("vlanDB updated: number of VMs in VLAN %d: %s" % (vlanId, vlanDB[vlanId][0]))
        return

    vx_dev_idx = Intf.GetIfIndex(nlm, vx_dev)
    vx_dev_name = Intf.GetVxlanIface(vlanId)
    vx_dev_config = True if vx_dev_idx or vx_dev_name else False
    if vxlan_config and not vx_dev_config:
        log_info("Adding VxLan device %s" % vx_dev)
        nlm.link_add_vxlan(vx_dev, vlanId, dstport=4789, local=vxlan_local_ip, learning=False, ageing=1800)
        vx_dev_idx = Intf.GetIfIndex(nlm, vx_dev)
        nlm.link_set_master(vx_dev, master_ifindex=bridge_idx)
        SetBridgeLearningOff(nlm, vx_dev)
        log_verbose("Deleting vlan 1 from %s" % vx_dev)
        nlm.vlan_modify(nlmanager.nlpacket.RTM_DELLINK, vx_dev_idx, 1, pvid=True, untagged=True)
        log_verbose("Adding vlan %d to %s" % (vlanId, vx_dev))
        nlm.vlan_modify(nlmanager.nlpacket.RTM_SETLINK, vx_dev_idx, vlanId, pvid=True, untagged=True)
        MstpVxlanConfig(bridge, vx_dev)
        nlm.link_set_updown(vx_dev, "up")

    bond_dict = {}
    bond_dict[bond] = [1, IsVlanConfiguredOnIface(nlm, bond, vlanId)]
    peerlink = Intf.GetPeerlink()
    peerlink_idx = Intf.GetIfIndex(nlm, peerlink)
    vlanDB[vlanId] = [1, bond_dict, IsVlanConfiguredOnIface(nlm, peerlink, vlanId),  IsVlanConfiguredOnIface(nlm, "bridge", vlanId), vx_dev_config]
    log_verbose("Vlan %d added to the vlanDB" % (vlanId))

    if not bond_dict[bond][1]:
        log_info("Adding vlan %d to %s" % (vlanId, bond))
        nlm.vlan_modify(nlmanager.nlpacket.RTM_SETLINK, bond_idx, vlanId, bridge_master=bridge_idx)
    if not vlanDB[vlanId][2]:
        log_info("Adding vlan %d to %s" % (vlanId, peerlink))
        nlm.vlan_modify(nlmanager.nlpacket.RTM_SETLINK, peerlink_idx, vlanId, bridge_master=bridge_idx)
    if not vlanDB[vlanId][3]:
        log_info("Adding vlan %d to the bridge" % vlanId)
        nlm.link_add_bridge_vlan(bridge_idx, vlanId)

def DelVlanConfig(nlm, bond, vlanId):
    if not vlanId:
        return
    bond_idx = Intf.GetIfIndex(nlm, bond)
    bridge = Intf.GetBridge()
    bridge_idx = Intf.GetIfIndex(nlm, bridge)
    vlan = vlanDB.get(vlanId, (0, {}, False, False, False))
    if vlan[0] > 1:
        vlanDB[vlanId][0] -= 1
        log_verbose("vlanDB updated: number of VMs in VLAN %d: %s" % (vlanId, vlanDB[vlanId][0]))
        if bond in vlanDB[vlanId][1]:
            if vlanDB[vlanId][1][bond][0] > 1:
                vlanDB[vlanId][1][bond][0] -= 1
                return
            if not vlanDB[vlanId][1][bond][1]:
                del vlanDB[vlanId][1][bond]
                log_info("Deleting vlan %d from %s" % (vlanId, bond))
                nlm.vlan_modify(nlmanager.nlpacket.RTM_DELLINK, bond_idx, vlanId, bridge_master=bridge_idx)
        return

    if bond in vlanDB[vlanId][1]:
        if not vlanDB[vlanId][1][bond][1]:
            del vlanDB[vlanId][1][bond]
            log_info("Deleting vlan %d from %s" % (vlanId, bond))
            nlm.vlan_modify(nlmanager.nlpacket.RTM_DELLINK, bond_idx, vlanId, bridge_master=bridge_idx)
    if not vlan[2]:
        peerlink = Intf.GetPeerlink()
        peerlink_idx = Intf.GetIfIndex(nlm, peerlink)
        log_info("Deleting vlan %d from %s" % (vlanId, peerlink))
        nlm.vlan_modify(nlmanager.nlpacket.RTM_DELLINK, peerlink_idx, vlanId, bridge_master=bridge_idx)
    if not vlan[3]:
        log_info("Deleting vlan %d from %s" % (vlanId, bridge))
        nlm.link_del_bridge_vlan(bridge_idx, vlanId)
    if not vlan[4] and vxlan_config:
        vx_dev = "vx-"+ str(vlanId)
        log_info("Deleting %s" % vx_dev)
        nlm.link_del(ifname=vx_dev)
    log_verbose("Deleting vlan %d from the vlanDB" % vlanId)
    del vlanDB[vlanId]

def ClearVlanConfig(nlm):
    #TODO: needs better dict handling
    bridge = Intf.GetBridge()
    bridge_idx = Intf.GetIfIndex(nlm, bridge)
    for vlanId, value in vlanDB.copy().iteritems():
        for bond, conf_value in value[1].iteritems():
           if not conf_value[1]:
                bond_idx = Intf.GetIfIndex(nlm, bond)
                log_info("Deleting vlan %d from %s" % (vlanId, bond))
                nlm.vlan_modify(nlmanager.nlpacket.RTM_DELLINK, bond_idx, vlanId, bridge_master=bridge_idx)
        if not value[2]:
            peerlink = Intf.GetPeerlink()
            peerlink_idx = Intf.GetIfIndex(nlm, peerlink)
            log_info("Deleting vlan %d from %s" % (vlanId, peerlink))
            nlm.vlan_modify(nlmanager.nlpacket.RTM_DELLINK, peerlink_idx, vlanId, bridge_master=bridge_idx)
        if not value[3]:
            log_info("Deleting vlan %d from %s" % (vlanId, bridge))
            nlm.link_del_bridge_vlan(bridge_idx, vlanId)
        if vxlan_config and not value[4]:
            vx_dev = "vx-"+ str(vlanId)
            log_info("Deleting %s" % vx_dev)
            nlm.link_del(ifname=vx_dev)
        log_verbose("Deleting vlan %d from the vlanDB" % vlanId)
        del vlanDB[vlanId]

def AddStaticMac(nlm, mac, intf, vlanId):
    #TODO: fix issues related to static mac programming
    return
    log_info("Adding static mac %s vlan %s to %s" % (mac, vlanId, intf))
    neigh = nlmanager.nlpacket.Neighbor(nlmanager.nlpacket.RTM_NEWNEIGH)
    neigh.flags = nlmanager.nlpacket.NLM_F_REQUEST |  nlmanager.nlpacket.NLM_F_CREATE | nlmanager.nlpacket.NLM_F_REPLACE
    neigh.family = socket.AF_BRIDGE
    ntf = neigh.NTF_MASTER
    nud_state = neigh.NUD_NOARP
    idx = Intf.GetIfIndex(nlm, intf)
    neigh.body = struct.pack(neigh.PACK, socket.AF_BRIDGE, idx, nud_state, ntf, 0)
    neigh.add_attribute(neigh.NDA_LLADDR, mac)
    if vlanId:
        neigh.add_attribute(neigh.NDA_VLAN, vlanId)
    neigh.build_message(nlm.sequence.next(), nlm.pid)
    nlm.tx_nlpacket_raw(neigh.message)

def DelStaticMac(nlm, mac, intf, vlanId):
    #TODO: fix issues related to static mac programming
    return
    log_info("Deleting static mac %s vlan %s from %s" % (mac, vlanId, intf))
    neigh = nlmanager.nlpacket.Neighbor(nlmanager.nlpacket.RTM_DELNEIGH)
    neigh.flags = nlmanager.nlpacket.NLM_F_REQUEST
    neigh.family = socket.AF_BRIDGE
    ntf = neigh.NTF_MASTER
    nud_state = neigh.NUD_NOARP
    idx = Intf.GetIfIndex(nlm, intf)
    neigh.body = struct.pack(neigh.PACK, socket.AF_BRIDGE, idx, nud_state, ntf, 0)
    neigh.add_attribute(neigh.NDA_LLADDR, mac)
    if vlanId:
        neigh.add_attribute(neigh.NDA_VLAN, vlanId)
    neigh.build_message(nlm.sequence.next(), nlm.pid)
    nlm.tx_nlpacket_raw(neigh.message)

def ClearStaticMac(nlm):
    for vm, [bond, vlanId, host, vm_name, mac] in vmDB.copy().iteritems():
        if bond:
            DelStaticMac(nlm, mac, bond, vlanId)

def stop_processing(level, status):
    if level >= 1:
        # Stop the lldp monitor
        if lldp_monitor:
            lldp_monitor.stop()
        # Stop the Periodic Sync
        if periodic_sync:
            periodic_sync.stop()
        # Stop the netlink listener
        if listener:
            listener.stop()
        # Stop the workq
        if wq:
            wq.stop()
        # Remove the vlan config if necessary
        nlm = nlmanager.nlmanager.NetlinkManager(_NLM_STOP)
        ClearStaticMac(nlm)
        ClearVlanConfig(nlm)
        if level >= 3 and wh_uuid:
            # Remove the webhook we added before deleting the clag bonds
            if wh.del_web_hook(wh_uuid):
                log_error("Error removing the WEB hook %s" % wh_uuid)

        # Remove any automatically added bonds
        for key, value in autobonds.copy().iteritems():
            DeleteClagBond(nlm, value[2][0])

    if level >= 2 and http_server:
        # Stop the WEB server
        http_server.stop()

    if status == 0:
        log_info("clean exit")
    else:
        log_error("exit with status %d" % status)
    sys.exit(status)


#-------------------------------------------------------------------------------
#
#   Main program entry point
#
#-------------------------------------------------------------------------------

def main():

    read_config()
    init_logging()

    # Set the timeout for socket operations, we don't want to wait forever
    socket.setdefaulttimeout(socket_timeout)

    # Interface utility routines
    nlm = nlmanager.nlmanager.NetlinkManager(_NLM_INTF)
    global Intf
    Intf = IntfSupport(nlm)

    # Start the listener
    global listener
    listener = NetlinkListener()

    # Create the work queue
    global wq
    wq = WorkQueue()

    # Start monitoring LLDP
    global lldp_monitor
    lldp_monitor = LldpMonitor()

    global subnets
    global hosts
    global vms
    global ntnx_rest_api
    global api_library
    ntnx_rest_api = NtnxRestApi(server, username, password)
    api_library = NtnxApiLibrary()
    subnets = SubnetClass(ntnx_rest_api, api_library)
    hosts = HostsClass(ntnx_rest_api, api_library)
    vms = VmsClass(ntnx_rest_api, api_library)

    missing_params = ""
    if not server:
        missing_params = "server "
    if not username:
        missing_params += "username "
    elif not password:
        missing_params += "password "
    if missing_params:
        log_error("Missing required parameters: %s" % missing_params)
        stop_processing(1, 1)

    # Start periodic sync
    global periodic_sync
    periodic_sync = PeriodicSync()

    if hook_server:
        WebHookInit(hook_server)

    elements = vms.get_running_vms()
    for element in elements.get('entities', []):
        wq.put("vm-add", element)

    listener.workq.put(('GET_ALL_LINKS', None))
    listener.workq.put(('GET_ALL_ADDRESSES', None))
    listener.main()
    stop_processing(3, 0)


#-------------------------------------------------------------------------------
#
#   Are we being executed or imported?
#
#-------------------------------------------------------------------------------

if __name__ == '__main__':
    status = 0
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGQUIT, signal_handler)
    try:
        main()
    except Exception:
        dump_traceback()
        status = 1
    stop_processing(3, status)