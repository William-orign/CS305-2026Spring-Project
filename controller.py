from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from os_ken.controller.handler import set_ev_cls
from os_ken.topology import event
from os_ken.topology.switches import Switch, Host, HostState, Port, PortState, PortData, PortDataState, Link, LinkState
from os_ken.topology.switches import Switches
from os_ken.ofproto import ofproto_v1_0, ether, inet
from os_ken.lib.packet import packet, ethernet, ether_types, arp
from os_ken.lib.packet import dhcp
from os_ken.lib.packet import ethernet
from os_ken.lib.packet import ipv4
from os_ken.lib.packet import packet
from os_ken.lib.packet import udp
from dhcp import DHCPServer
from collections import defaultdict
import time
from ofctl_utilis import OfCtl,OfCtl_v1_0,OfCtl_after_v1_2,VLANID_NONE
import logging
import copy
import heapq
from firewall import Firewall


class ControllerApp(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ControllerApp, self).__init__(*args, **kwargs)
        # 记录 dpid -> (mac -> port) 的映射，用于学习交换功能
        self.mac_to_port = {}

    @set_ev_cls(event.EventSwitchEnter)
    def handle_switch_add(self, ev):
        """
        Event handler indicating a switch has come online.
        """

    @set_ev_cls(event.EventSwitchLeave)
    def handle_switch_delete(self, ev):
        """
        Event handler indicating a switch has been removed
        """


    @set_ev_cls(event.EventHostAdd)
    def handle_host_add(self, ev):
        """
        Event handler indiciating a host has joined the network
        This handler is automatically triggered when a host sends an ARP response.
        """ 
        # TODO:  Update network topology and flow rules

    @set_ev_cls(event.EventLinkAdd)
    def handle_link_add(self, ev):
        """
        Event handler indicating a link between two switches has been added
        """
        # TODO:  Update network topology and flow rules

    @set_ev_cls(event.EventLinkDelete)
    def handle_link_delete(self, ev):
        """
        Event handler indicating when a link between two switches has been deleted
        """
        # TODO:  Update network topology and flow rules
   
        

    @set_ev_cls(event.EventPortModify)
    def handle_port_modify(self, ev):
        """
        Event handler for when any switch port changes state.
        This includes links for hosts as well as links between switches.
        """
        # TODO:  Update network topology and flow rules



    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        try:
            msg = ev.msg
            datapath = msg.datapath
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            in_port = msg.in_port

            pkt = packet.Packet(data=msg.data)
            eth = pkt.get_protocol(ethernet.ethernet)

            # ignore lldp to avoid topology discovery noise
            if eth and eth.ethertype == ether_types.ETH_TYPE_LLDP:
                return

            # DHCP handling (preserve existing behavior)
            dhcp_pkt = pkt.get_protocol(dhcp.dhcp)
            if dhcp_pkt:
                DHCPServer.handle_dhcp(datapath, in_port, pkt)
                return

            # ===== Learning switch behavior =====
            dpid = datapath.id
            self.mac_to_port.setdefault(dpid, {})

            src = eth.src
            dst = eth.dst

            # learn source MAC -> port
            self.mac_to_port[dpid][src] = in_port

            # decide out port
            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
            else:
                out_port = ofproto.OFPP_FLOOD

            actions = [parser.OFPActionOutput(out_port, 0)]

            # 如果知道目标端口，为该流下发一条临时流表，避免后续触发 PacketIn
            if out_port != ofproto.OFPP_FLOOD:
                # 仅针对单播流下发流表，广播/泛洪包不应安装流表
                try:
                    match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
                except Exception:
                    # 兼容不同版本的 match 字段名称
                    match = parser.OFPMatch(in_port=in_port, dl_dst=dst, dl_src=src)

                # 构造 FlowMod，安装并让交换机后续自行转发
                try:
                    mod = parser.OFPFlowMod(datapath=datapath, match=match, cookie=0,
                                            command=ofproto.OFPFC_ADD, idle_timeout=10, hard_timeout=30,
                                            priority=1, buffer_id=msg.buffer_id,
                                            out_port=ofproto.OFPP_NONE, actions=actions)
                    datapath.send_msg(mod)
                    return
                except Exception:
                    # 若 FlowMod 构造不兼容，回退到发送 PacketOut（确保功能）
                    pass

            # 对于需要泛洪或 FlowMod 构造失败的情况，发送 PacketOut
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            out = parser.OFPPacketOut(datapath=datapath,
                                      buffer_id=msg.buffer_id,
                                      in_port=in_port,
                                      actions=actions,
                                      data=data)
            datapath.send_msg(out)
            return
        except Exception as e:
            self.logger.error(e)
    