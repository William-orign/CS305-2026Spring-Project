# firewall.py

import json
import os
import socket
import struct
from dataclasses import dataclass

from os_ken.ofproto import ether, inet


@dataclass(frozen=True)
class FirewallRule:
    src_ip: str = None
    dst_ip: str = None
    proto: str = None
    src_port: object = None
    dst_port: object = None
    action: str = "deny"


class Firewall:
    COOKIE = 0x305F
    PRIORITY = 60000

    PROTO_MAP = {
        None: 0,
        "": 0,
        "*": 0,
        "any": 0,
        "icmp": inet.IPPROTO_ICMP,
        "tcp": inet.IPPROTO_TCP,
        "udp": inet.IPPROTO_UDP,
    }

    def __init__(self, rule_file="firewall_rule.json"):
        self.rule_file = rule_file
        self.rules = self._load_rules(rule_file)
        self.installed = set()
        # Last modification time of firewall_rule.json.
        self.last_mtime = self._get_rule_mtime()

    # Some helper functions that may be useful
    def _normalize_any(self, value):
        if value is None:
            return None
        if isinstance(value, str) and value.strip().lower() in ["", "*", "any"]:
            return None
        return value

    def _normalize_proto(self, proto):
        proto = self._normalize_any(proto)
        if proto is None:
            return None
        return str(proto).lower()

    def _proto_to_number(self, proto):
        proto = self._normalize_proto(proto)
        return self.PROTO_MAP.get(proto, 0)

    def _normalize_port(self, value):
        value = self._normalize_any(value)
        if value is None:
            return 0
        return int(value)
    
    def _prepare_rule(self, rule):
        """
        Normalize and validate one firewall rule.

        Return:
            (src_ip, dst_ip, proto_num, src_port, dst_port, action)

        Return None if the rule should be skipped.
        """
        # 1. Only handle deny rules
        action = str(rule.action).strip().lower()
        if action != "deny":
            return None

        # 2. Normalize source IP and destination IP
        src_ip = self._normalize_any(rule.src_ip)
        dst_ip = self._normalize_any(rule.dst_ip)

        # 3. Normalize protocol name
        proto = self._normalize_proto(rule.proto)

        # Skip unsupported protocol names
        if proto not in self.PROTO_MAP:
            print(f"[Firewall] Skip unsupported protocol rule: {rule}")
            return None

        # 4. Convert protocol name to protocol number
        proto_num = self._proto_to_number(proto)

        # 5. Normalize source and destination ports
        try:
            src_port = self._normalize_port(rule.src_port)
            dst_port = self._normalize_port(rule.dst_port)
        except Exception as e:
            print(f"[Firewall] Skip invalid port rule {rule}: {e}")
            return None

        # 6. Check port range
        if src_port < 0 or src_port > 65535:
            print(f"[Firewall] Skip invalid source port rule: {rule}")
            return None

        if dst_port < 0 or dst_port > 65535:
            print(f"[Firewall] Skip invalid destination port rule: {rule}")
            return None

        # 7. Ports are only valid for TCP or UDP
        has_port = src_port != 0 or dst_port != 0
        if (has_port) and (proto_num not in [inet.IPPROTO_TCP, inet.IPPROTO_UDP]):
            print(f"[Firewall] Skip port rule without TCP/UDP: {rule}")
            return None

        return src_ip, dst_ip, proto_num, src_port, dst_port, action

    def _load_rules(self, rule_file):
        #Load firewall rules from firewall_rule.json and return a list of FirewallRule.
        rules = []
        # 1. Read and parse JSON file
        with open(rule_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        # 2. Get rule list from JSON
        rule_items = data.get("rules", [])
        # 3. Convert each JSON rule into a FirewallRule object
        for item in rule_items:
            rule = FirewallRule(
                src_ip=self._normalize_any(item.get("src_ip")),
                dst_ip=self._normalize_any(item.get("dst_ip")),
                proto=self._normalize_proto(item.get("proto")),
                src_port=self._normalize_any(item.get("src_port")),
                dst_port=self._normalize_any(item.get("dst_port")),
                action=str(item.get("action", "deny")).strip().lower(),
            )
            rules.append(rule)
        print(f"[Firewall] Loaded {len(rules)} firewall rule(s) from {rule_file}")
        return rules
    
    def _get_rule_mtime(self):
        """
        Return the modification time of firewall_rule.json.
        """
        try:
            return os.path.getmtime(self.rule_file)
        except OSError:
            return None

    def rule_file_changed(self):
        """
        Check whether firewall_rule.json has been modified.
        """
        current_mtime = self._get_rule_mtime()

        if current_mtime is None:
            return False

        if self.last_mtime is None:
            self.last_mtime = current_mtime
            return False

        return current_mtime != self.last_mtime

    def mark_rule_file_seen(self):
        """
        Mark the current rule file version as handled.
        """
        self.last_mtime = self._get_rule_mtime()

    def install_rules(self, ofctls):
        """
        Install firewall rules to all switches.
        """
        for dpid, ofctl in ofctls.items():
            for rule in self.rules:
                prepared = self._prepare_rule(rule)

                if prepared is None:
                    continue

                src_ip, dst_ip, proto_num, src_port, dst_port, action = prepared

                # Avoid duplicated flow installation
                key = (
                    dpid,
                    src_ip,
                    dst_ip,
                    proto_num,
                    src_port,
                    dst_port,
                    action,
                )

                if key in self.installed:
                    continue

                # Install a high-priority drop flow
                ofctl.set_flow(
                    cookie=self.COOKIE,
                    priority=self.PRIORITY,
                    dl_type=ether.ETH_TYPE_IP,
                    nw_src=src_ip or 0,
                    nw_dst=dst_ip or 0,
                    nw_proto=proto_num,
                    tp_src=src_port,
                    tp_dst=dst_port,
                    actions=[]
                )

                self.installed.add(key)

                print(f"[Firewall] Installed deny rule on switch {dpid}: {rule}")
    
    def _ipv4_to_int(self, ip):
        """
        Convert dotted IPv4 string to OpenFlow 1.0 integer format.
        """
        return struct.unpack("!I", socket.inet_aton(ip))[0]

    def _get_datapath_from_ofctl(self, ofctl):
        """
        Get datapath from OfCtl object.

        Different helper implementations may use different attribute names.
        """
        if hasattr(ofctl, "dp"):
            return ofctl.dp

        if hasattr(ofctl, "datapath"):
            return ofctl.datapath

        raise AttributeError("Cannot find datapath in OfCtl object")

    def clear_installed_for_switch(self, dpid):
        self.installed = {
            key for key in self.installed
            if key[0] != dpid
        }
    def _build_delete_match(self, ofctl, src_ip, dst_ip, proto_num, src_port, dst_port):
        """
        Build the OpenFlow 1.0 match for deleting an old firewall flow.
        The match must be consistent with the match used when installing
        the firewall drop flow.
        """
        dp = self._get_datapath_from_ofctl(ofctl)
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        wildcards = ofp.OFPFW_ALL

        # Firewall rules only match IPv4 packets.
        dl_type = ether.ETH_TYPE_IP
        wildcards &= ~ofp.OFPFW_DL_TYPE

        # Source IP.
        if src_ip:
            nw_src = self._ipv4_to_int(src_ip)
            wildcards &= ~ofp.OFPFW_NW_SRC_MASK
        else:
            nw_src = 0

        # Destination IP.
        if dst_ip:
            nw_dst = self._ipv4_to_int(dst_ip)
            wildcards &= ~ofp.OFPFW_NW_DST_MASK
        else:
            nw_dst = 0

        # IP protocol: ICMP/TCP/UDP.
        if proto_num:
            wildcards &= ~ofp.OFPFW_NW_PROTO

        # Transport source port.
        if src_port:
            wildcards &= ~ofp.OFPFW_TP_SRC

        # Transport destination port.
        if dst_port:
            wildcards &= ~ofp.OFPFW_TP_DST

        return parser.OFPMatch(
            wildcards,
            0,          # in_port
            0,          # dl_src
            0,          # dl_dst
            0,          # dl_vlan
            0,          # dl_vlan_pcp
            dl_type,
            0,          # nw_tos
            proto_num,
            nw_src,
            nw_dst,
            src_port,
            dst_port
        )
    
    def _delete_firewall_flow(self, ofctl, src_ip, dst_ip, proto_num, src_port, dst_port):
        """
        Delete one old firewall flow from one switch.

        OpenFlow 1.0 cannot delete firewall flows by cookie mask,
        so we delete by strict match and priority.
        """
        dp = self._get_datapath_from_ofctl(ofctl)
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        match = self._build_delete_match(
            ofctl,
            src_ip,
            dst_ip,
            proto_num,
            src_port,
            dst_port
        )

        mod = parser.OFPFlowMod(
            datapath=dp,
            match=match,
            cookie=self.COOKIE,
            command=ofp.OFPFC_DELETE_STRICT,
            idle_timeout=0,
            hard_timeout=0,
            priority=self.PRIORITY,
            buffer_id=0xffffffff,
            out_port=ofp.OFPP_NONE,
            flags=0,
            actions=[]
        )

        dp.send_msg(mod)
    def delete_rules(self, ofctls, rules=None):
        """
        Delete old firewall rules from all switches.
        """
        if rules is None:
            rules = self.rules

        for dpid, ofctl in ofctls.items():
            for rule in rules:
                prepared = self._prepare_rule(rule)

                if prepared is None:
                    continue

                src_ip, dst_ip, proto_num, src_port, dst_port, action = prepared

                self._delete_firewall_flow(
                    ofctl,
                    src_ip,
                    dst_ip,
                    proto_num,
                    src_port,
                    dst_port
                )

                print(f"[Firewall] Deleted old deny rule on switch {dpid}: {rule}")

        self.installed.clear()
    
    def reload_rules(self, ofctls):
        """
        Dynamically reload firewall rules.

        Important order:
        1. Parse new JSON first.
        2. If parsing succeeds, delete old switch flows.
        3. Replace self.rules.
        4. Install new flows.
        """
        # Parse new rules first.
        # If JSON is invalid, an exception is raised and old flows remain active.
        new_rules = self._load_rules(self.rule_file)

        old_rules = list(self.rules)

        # Delete old firewall flows from switches.
        self.delete_rules(ofctls, old_rules)

        # Replace controller-side rules.
        self.rules = new_rules
        self.installed.clear()
        self.last_mtime = self._get_rule_mtime()

        # Install new rules.
        self.install_rules(ofctls)

        print(f"[Firewall] Reload completed. Active rule count = {len(self.rules)}")
