# firewall.py

import json
import os
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

    def install_rules(self, ofctls):
        """
        Install firewall rules to all switches.
        """
        for dpid, ofctl in ofctls.items():
            for rule in self.rules:

                # 1. Only handle deny rules
                action = str(rule.action).strip().lower()
                if action != "deny":
                    continue
                # 2. Normalize source IP and destination IP
                src_ip = self._normalize_any(rule.src_ip)
                dst_ip = self._normalize_any(rule.dst_ip)
                # 3. Normalize protocol name
                proto = self._normalize_proto(rule.proto)

                # Skip unsupported protocol names
                if proto not in self.PROTO_MAP:
                    print(f"[Firewall] Skip unsupported protocol rule: {rule}")
                    continue

                # 4. Convert protocol name to protocol number
                proto_num = self._proto_to_number(proto)

                # 5. Normalize source and destination ports
                try:
                    src_port = self._normalize_port(rule.src_port)
                    dst_port = self._normalize_port(rule.dst_port)
                except Exception as e:
                    print(f"[Firewall] Skip invalid port rule {rule}: {e}")
                    continue

                # 6. Check port range
                if src_port < 0 or src_port > 65535:
                    print(f"[Firewall] Skip invalid source port rule: {rule}")
                    continue

                if dst_port < 0 or dst_port > 65535:
                    print(f"[Firewall] Skip invalid destination port rule: {rule}")
                    continue

                # 7. Ports are only valid for TCP or UDP
                has_port = src_port != 0 or dst_port != 0
                if has_port and proto_num not in [inet.IPPROTO_TCP, inet.IPPROTO_UDP]:
                    print(f"[Firewall] Skip port rule without TCP/UDP: {rule}")
                    continue

                # 8. Avoid duplicated flow installation
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

                # 9. Install a high-priority drop flow
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
                
    def clear_installed_for_switch(self, dpid):
        self.installed = {
            key for key in self.installed
            if key[0] != dpid
        }
