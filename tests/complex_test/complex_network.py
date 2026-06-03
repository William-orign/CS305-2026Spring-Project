
"""
Complex robustness testcase for CS305 controller.

This version DOES NOT modify firewall_rule.json.

Use this when you want to manually maintain firewall_rule.json and let the
controller load it on startup.

Manual DHCP mapping expected by this testcase:
    h1 = 192.168.1.2
    h2 = 192.168.1.3
    h3 = 192.168.1.4
    h4 = 192.168.1.5
    h5 = 192.168.1.6
    h6 = 192.168.1.7
    h7 = 192.168.1.8
    h8 = 192.168.1.9

Expected firewall policy:
    deny h1 -> h5 TCP:3306
    deny h2 -> h5 TCP:3306
    deny h3 -> h5 TCP:3306
    deny h8 -> h5 TCP:3306
    deny h3 -> h6 TCP:22
    deny h1 -> h4 TCP:80

Topology overview:

Main chain:
    s1 -- s2 -- s3 -- s4 -- s5 -- s6

Shortcut links:
    s2 -- s5
    s3 -- s6

Diamond / equal-cost / cyclic structure:
    s2 -- s7 -- s4
    s2 -- s8 -- s4
    s7 -- s8

Hosts:
    h1, h2 on s1       normal clients
    h3     on s2       guest / untrusted host
    h4     on s6       web server / DMZ
    h5     on s5       database server / internal server
    h6     on s4       admin host
    h7     on s3       log / DNS server
    h8     on s8       contractor / semi-trusted host
"""

import argparse
import os
import re
import sys
import time
from collections import defaultdict, deque

from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel, info
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.topo import Topo


EXPECTED_IP_MAP = {
    "h1": "192.168.1.2",
    "h2": "192.168.1.3",
    "h3": "192.168.1.4",
    "h4": "192.168.1.5",
    "h5": "192.168.1.6",
    "h6": "192.168.1.7",
    "h7": "192.168.1.8",
    "h8": "192.168.1.9",
}


HOST_SWITCH = {
    "h1": "s1",
    "h2": "s1",
    "h3": "s2",
    "h4": "s6",
    "h5": "s5",
    "h6": "s4",
    "h7": "s3",
    "h8": "s8",
}


SWITCH_LINKS = [
    ("s1", "s2"),
    ("s2", "s3"),
    ("s3", "s4"),
    ("s4", "s5"),
    ("s5", "s6"),
    ("s2", "s5"),
    ("s3", "s6"),
    ("s2", "s7"),
    ("s7", "s4"),
    ("s2", "s8"),
    ("s8", "s4"),
    ("s7", "s8"),
]


SHORTEST_PATH_AUDIT_PAIRS = [
    ("h1", "h4", "client to DMZ web server; should use shortcut"),
    ("h7", "h4", "log/DNS host to web server; should use direct s3-s6 shortcut"),
    ("h3", "h6", "guest to admin; equal-cost diamond area"),
    ("h1", "h5", "client to database host; should use s2-s5 shortcut"),
    ("h8", "h4", "contractor to web server"),
    ("h2", "h4", "another client to web server"),
    ("h4", "h5", "web server to database server"),
    ("h1", "h6", "client to admin host"),
]


class RobustComplexTopo(Topo):
    """8-switch, 8-host topology with shortcuts, cycles, and equal-cost paths."""

    def build(self):
        # Hosts. DHCP will assign final IPs.
        h1 = self.addHost("h1", ip="0.0.0.0")
        h2 = self.addHost("h2", ip="0.0.0.0")
        h3 = self.addHost("h3", ip="0.0.0.0")
        h4 = self.addHost("h4", ip="0.0.0.0")
        h5 = self.addHost("h5", ip="0.0.0.0")
        h6 = self.addHost("h6", ip="0.0.0.0")
        h7 = self.addHost("h7", ip="0.0.0.0")
        h8 = self.addHost("h8", ip="0.0.0.0")

        # Switches.
        # Do NOT force OpenFlow13 here. The current project controller uses OpenFlow 1.0.
        s1 = self.addSwitch("s1")
        s2 = self.addSwitch("s2")
        s3 = self.addSwitch("s3")
        s4 = self.addSwitch("s4")
        s5 = self.addSwitch("s5")
        s6 = self.addSwitch("s6")
        s7 = self.addSwitch("s7")
        s8 = self.addSwitch("s8")

        # Host access links.
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s2)
        self.addLink(h4, s6)
        self.addLink(h5, s5)
        self.addLink(h6, s4)
        self.addLink(h7, s3)
        self.addLink(h8, s8)

        # Main chain.
        self.addLink(s1, s2)
        self.addLink(s2, s3)
        self.addLink(s3, s4)
        self.addLink(s4, s5)
        self.addLink(s5, s6)

        # Shortcut links.
        self.addLink(s2, s5)
        self.addLink(s3, s6)

        # Diamond / equal-cost / cyclic substructure.
        self.addLink(s2, s7)
        self.addLink(s7, s4)
        self.addLink(s2, s8)
        self.addLink(s8, s4)
        self.addLink(s7, s8)


def get_host_ip(host) -> str:
    """Read the current IPv4 address of a Mininet host's default interface."""
    intf = host.defaultIntf().name
    out = host.cmd(
        "ip -4 -o addr show dev %s | awk '{split($4,a,\"/\"); print a[1]}'" % intf
    ).strip()

    for token in out.split():
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", token) and token != "0.0.0.0":
            return token

    return ""


def run_dhcp(host, timeout_sec: int = 10) -> str:
    """Request an IP address from the controller DHCP server."""
    intf = host.defaultIntf().name

    host.cmd("pkill -f 'dhclient.*%s' >/dev/null 2>&1 || true" % intf)
    host.cmd("dhclient -r %s >/dev/null 2>&1 || true" % intf)
    host.cmd("ip addr flush dev %s >/dev/null 2>&1 || true" % intf)

    out = host.cmd(
        "timeout %d dhclient -v -1 %s 2>&1 || true" % (timeout_sec, intf)
    )

    ip = get_host_ip(host)

    if not ip:
        info("*** DHCP output for %s:\n%s\n" % (host.name, out))

    return ip


def start_http_server(host, port: int):
    """Start a simple TCP service using Python's HTTP server."""
    host.cmd("pkill -f 'python3 -m http.server %d' >/dev/null 2>&1 || true" % port)
    host.cmd(
        "nohup python3 -m http.server %d --bind 0.0.0.0 "
        "> /tmp/%s_http_%d.log 2>&1 &" % (port, host.name, port)
    )


def stop_http_servers(hosts):
    for h in hosts:
        h.cmd("pkill -f 'python3 -m http.server' >/dev/null 2>&1 || true")


def ping_ok(src, dst_ip: str, count: int = 3, attempts: int = 4) -> bool:
    """
    Return True if ICMP succeeds.

    The first packet may trigger host learning, ARP handling, and flow installation,
    so retrying avoids false negatives.
    """
    for _ in range(attempts):
        out = src.cmd("ping -c %d -W 2 %s 2>&1 || true" % (count, dst_ip))
        if (" 0% packet loss" in out) or (", 0% packet loss" in out):
            return True
        time.sleep(1)

    return False


def tcp_http_ok(src, dst_ip: str, port: int, timeout_sec: int = 3, attempts: int = 3) -> bool:
    """
    Return True if TCP connection + HTTP request succeeds.
    """
    for _ in range(attempts):
        out = src.cmd(
            "curl --connect-timeout 2 -m %d -sS -o /dev/null -w '%%{http_code}' "
            "http://%s:%d/ 2>/dev/null || true" % (timeout_sec, dst_ip, port)
        ).strip()

        if out.startswith("2") or out.startswith("3") or out == "404":
            return True

        time.sleep(1)

    return False


def warm_up_paths(hosts_by_name: dict, ip_map: dict):
    """
    Warm up ARP, host learning, and route flow installation before scored tests.

    This warm-up uses ICMP only. It does not send traffic to the tested TCP ports,
    so it does not bypass firewall tests such as h1 -> h4:80 or h1 -> h5:3306.
    """
    print("*** Warming up host learning and route flows")

    names = sorted(hosts_by_name.keys())

    # Stage 1: make every host actively send one packet with its DHCP IP.
    # This helps the controller learn real source IP -> switch -> port.
    for src_name in names:
        if src_name == "h1":
            dst_name = "h4"
        else:
            dst_name = "h1"

        src = hosts_by_name[src_name]
        dst_ip = ip_map[dst_name]
        src.cmd("ping -c 1 -W 1 %s >/dev/null 2>&1 || true" % dst_ip)

    time.sleep(1)

    # Stage 2: bidirectional warm-up for paths used by scored tests.
    important_pairs = [
        ("h1", "h4"),
        ("h7", "h4"),
        ("h3", "h6"),
        ("h1", "h5"),
        ("h8", "h4"),
        ("h4", "h5"),
        ("h1", "h6"),
        ("h2", "h4"),
    ]

    for a, b in important_pairs:
        host_a = hosts_by_name[a]
        host_b = hosts_by_name[b]

        host_a.cmd("ping -c 1 -W 1 %s >/dev/null 2>&1 || true" % ip_map[b])
        host_b.cmd("ping -c 1 -W 1 %s >/dev/null 2>&1 || true" % ip_map[a])

    time.sleep(2)


def show_topology_design():
    print("\n========== Complex Topology Design ==========")
    print("Main chain:       s1 -- s2 -- s3 -- s4 -- s5 -- s6")
    print("Shortcut links:   s2 -- s5, s3 -- s6")
    print("Diamond/cycles:   s2 -- s7 -- s4, s2 -- s8 -- s4, s7 -- s8")
    print("Hosts:")
    print("  h1,h2: clients on s1")
    print("  h3:    guest on s2")
    print("  h4:    web server / DMZ on s6")
    print("  h5:    database server on s5")
    print("  h6:    admin host on s4")
    print("  h7:    log/DNS host on s3")
    print("  h8:    contractor host on s8")
    print("\nShortest-path examples expected from topology:")
    print("  h1 -> h4 should use a shortcut path such as s1-s2-s3-s6 or s1-s2-s5-s6")
    print("  h7 -> h4 should prefer s3-s6 instead of the longer s3-s4-s5-s6")
    print("  h3 -> h6 has multiple equal-cost candidates through s3, s7, or s8")
    print("============================================\n")


def print_expected_firewall_policy():
    print("\n========== Expected Manual Firewall Rules ==========")
    print("Please make sure firewall_rule.json is manually written before starting controller.py.")
    print("Expected denies:")
    print("  h1(192.168.1.2) -> h5(192.168.1.6) TCP:3306")
    print("  h2(192.168.1.3) -> h5(192.168.1.6) TCP:3306")
    print("  h3(192.168.1.4) -> h5(192.168.1.6) TCP:3306")
    print("  h8(192.168.1.9) -> h5(192.168.1.6) TCP:3306")
    print("  h3(192.168.1.4) -> h6(192.168.1.7) TCP:22")
    print("  h1(192.168.1.2) -> h4(192.168.1.5) TCP:80")
    print("====================================================\n")


def verify_expected_ip_map(ip_map: dict) -> bool:
    """
    Verify actual DHCP allocation against the firewall file assumed by this testcase.
    """
    ok = True

    print("\n========== DHCP IP Map ==========")
    for name in sorted(ip_map):
        actual = ip_map[name]
        expected = EXPECTED_IP_MAP.get(name)
        mark = "OK" if actual == expected else "MISMATCH"
        print("%s = %s    expected=%s    %s" % (name, actual, expected, mark))
        if actual != expected:
            ok = False
    print("=================================\n")

    if not ok:
        print("[WARNING] DHCP allocation does not match the manual firewall_rule.json assumption.")
        print("[WARNING] Firewall tests may fail because rules use fixed IP addresses.\n")

    return ok



def build_switch_graph():
    """Build an undirected switch graph from SWITCH_LINKS."""
    graph = defaultdict(list)

    for a, b in SWITCH_LINKS:
        graph[a].append(b)
        graph[b].append(a)

    return graph


def all_shortest_switch_paths(src_sw: str, dst_sw: str):
    """
    Return all shortest paths from src_sw to dst_sw on the designed switch graph.
    Each path is a list of switch names.
    """
    graph = build_switch_graph()

    queue = deque([[src_sw]])
    shortest_len = None
    results = []

    while queue:
        path = queue.popleft()
        node = path[-1]

        if shortest_len is not None and len(path) > shortest_len:
            continue

        if node == dst_sw:
            shortest_len = len(path)
            results.append(path)
            continue

        for nxt in sorted(graph[node]):
            if nxt not in path:
                queue.append(path + [nxt])

    return results


def path_to_edges(path):
    """Convert ['s1','s2','s3'] to sorted undirected edge tuples."""
    edges = []

    for i in range(len(path) - 1):
        a, b = path[i], path[i + 1]
        edges.append(tuple(sorted((a, b))))

    return edges


def read_intf_packets(node, intf_name: str) -> int:
    """
    Read rx_packets + tx_packets for an interface.

    OVS switch ports are visible in /sys/class/net in the root namespace.
    """
    out = node.cmd(
        "cat /sys/class/net/%s/statistics/rx_packets "
        "/sys/class/net/%s/statistics/tx_packets 2>/dev/null || true"
        % (intf_name, intf_name)
    ).strip().split()

    total = 0
    for x in out:
        try:
            total += int(x)
        except ValueError:
            pass

    return total


def get_switch_link_counters(net):
    """
    Return packet counters for each inter-switch link.

    Counter key:
        ('s1', 's2')    # sorted tuple

    Counter value:
        rx+tx packet total on both switch-side interfaces.
    """
    counters = {}

    for a, b in SWITCH_LINKS:
        sw_a = net.get(a)
        sw_b = net.get(b)
        conns = sw_a.connectionsTo(sw_b)

        if not conns:
            counters[tuple(sorted((a, b)))] = 0
            continue

        # Only one physical link is expected between each pair.
        intf_a, intf_b = conns[0]
        total = (
            read_intf_packets(sw_a, intf_a.name)
            + read_intf_packets(sw_b, intf_b.name)
        )

        counters[tuple(sorted((a, b)))] = total

    return counters


def observed_switch_edges_for_ping(net, src_host, dst_ip: str, min_delta: int = 2):
    """
    Run one ping and infer which inter-switch links carried traffic.

    Because ARP/host learning may add noise, this function should be called
    after warm_up_paths(). min_delta filters very small background changes.
    """
    before = get_switch_link_counters(net)

    src_host.cmd("ping -c 3 -W 1 %s >/dev/null 2>&1 || true" % dst_ip)
    time.sleep(0.5)

    after = get_switch_link_counters(net)

    active = []
    deltas = {}

    for edge in sorted(before):
        delta = after.get(edge, 0) - before.get(edge, 0)
        deltas[edge] = delta

        if delta >= min_delta:
            active.append(edge)

    return active, deltas


def shortest_len_in_observed_edges(src_sw: str, dst_sw: str, observed_edges):
    """
    Compute the shortest path length using only observed active edges.
    Returns None if no path exists.
    """
    graph = defaultdict(list)

    for a, b in observed_edges:
        graph[a].append(b)
        graph[b].append(a)

    queue = deque([(src_sw, 0)])
    seen = {src_sw}

    while queue:
        node, dist = queue.popleft()

        if node == dst_sw:
            return dist

        for nxt in graph[node]:
            if nxt not in seen:
                seen.add(nxt)
                queue.append((nxt, dist + 1))

    return None


def audit_one_shortest_path_ping(net, ip_map: dict, src_name: str, dst_name: str, note: str):
    """
    Compare the observed inter-switch links for one ping with computed shortest paths.
    """
    src_sw = HOST_SWITCH[src_name]
    dst_sw = HOST_SWITCH[dst_name]

    expected_paths = all_shortest_switch_paths(src_sw, dst_sw)
    expected_hops = len(expected_paths[0]) - 1 if expected_paths else None
    expected_edge_sets = [set(path_to_edges(p)) for p in expected_paths]

    src_host = net.get(src_name)
    dst_ip = ip_map[dst_name]

    observed_edges, deltas = observed_switch_edges_for_ping(net, src_host, dst_ip)
    observed_edge_set = set(observed_edges)

    observed_shortest_hops = shortest_len_in_observed_edges(
        src_sw, dst_sw, observed_edges
    )

    # Accept if the active edges contain at least one complete shortest path.
    # This handles symmetric request/reply traffic and equal-cost tie-breaking.
    contains_shortest_path = any(
        edge_set.issubset(observed_edge_set) for edge_set in expected_edge_sets
    )

    # Also require that the observed active graph does not need a longer route
    # between src and dst.
    length_ok = observed_shortest_hops == expected_hops

    passed = contains_shortest_path and length_ok

    status = "PASS" if passed else "FAIL"

    print("[%s] ShortestPath: %s -> %s  %s" % (status, src_name, dst_name, note))
    print("       src_sw=%s dst_sw=%s expected_hops=%s observed_hops=%s" %
          (src_sw, dst_sw, expected_hops, observed_shortest_hops))
    print("       expected shortest paths:")
    for p in expected_paths:
        print("         " + " -> ".join(p))
    print("       observed active switch links:")
    if observed_edges:
        print("         " + ", ".join("%s-%s(delta=%d)" % (a, b, deltas[(a, b)]) for a, b in observed_edges))
    else:
        print("         <none>")
    print("")

    return passed


def run_shortest_path_audit(net, ip_map: dict):
    """
    Run ping-based shortest path audit for selected host pairs.
    """
    print("\n========== Shortest Path Audit ==========")
    print("Method: compare switch-link packet counter deltas before/after each ping.")
    print("Note: equal-cost shortest paths are all accepted.\n")

    total = 0
    passed = 0

    for src_name, dst_name, note in SHORTEST_PATH_AUDIT_PAIRS:
        total += 1
        if audit_one_shortest_path_ping(net, ip_map, src_name, dst_name, note):
            passed += 1

    print("Shortest path audit summary: %d/%d passed" % (passed, total))
    print("=========================================\n")

    return passed == total


def dump_flow_evidence(net, switches, title: str):
    print("\n========== Flow Table Evidence: %s ==========" % title)
    for sw_name in switches:
        print("\n--- %s flows ---" % sw_name)
        print(
            net.get(sw_name).cmd(
                "ovs-ofctl -O OpenFlow10 dump-flows %s | sed -n '1,40p'" % sw_name
            )
        )
    print("================================================\n")


def print_result(name: str, ok: bool, expected: bool) -> bool:
    passed = ok == expected
    status = "PASS" if passed else "FAIL"
    actual = "success" if ok else "blocked/failed"
    expect = "success" if expected else "blocked/failed"
    print("[%-4s] %-65s actual=%-15s expected=%s" % (status, name, actual, expect))
    return passed


def run_tests(args) -> int:
    topo = RobustComplexTopo()

    net = Mininet(
        topo=topo,
        controller=None,
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=True,
        autoStaticArp=False,
        build=True,
    )

    net.addController(
        "c0",
        controller=RemoteController,
        ip=args.controller_ip,
        port=args.controller_port,
    )

    show_topology_design()
    print_expected_firewall_policy()

    info("*** Starting network\n")
    net.start()

    hosts = [net.get("h%d" % i) for i in range(1, 9)]

    try:
        info("*** Waiting for switches to connect to controller\n")
        time.sleep(args.initial_wait)

        info("*** Requesting DHCP addresses for all hosts\n")
        ip_map = {}

        for h in hosts:
            ip = run_dhcp(h, args.dhcp_timeout)
            ip_map[h.name] = ip
            print("%s -> %s" % (h.name, ip if ip else "NO_IP"))

        if any(not ip for ip in ip_map.values()):
            print("\n[ERROR] Some hosts failed to obtain DHCP addresses.")
            print("Check whether controller.py is running and whether DHCP is implemented correctly.")
            return 1

        verify_expected_ip_map(ip_map)

        info("*** Starting test TCP services\n")
        h1, h2, h3, h4, h5, h6, h7, h8 = hosts

        # h4: web server, port 80.
        # h5: database-like service, port 3306.
        # h6: admin-like service, port 22.
        start_http_server(h4, 80)
        start_http_server(h5, 3306)
        start_http_server(h6, 22)
        time.sleep(2)

        hosts_by_name = {h.name: h for h in hosts}
        warm_up_paths(hosts_by_name, ip_map)

        if args.shortest_path_audit:
            run_shortest_path_audit(net, ip_map)

        print("\n========== Test Results ==========")
        total = 0
        passed = 0

        def check(name, actual, expected):
            nonlocal total, passed
            total += 1
            if print_result(name, actual, expected):
                passed += 1

        # Routing / shortest path connectivity.
        check("Routing: h1 ping h4 across shortcut-rich topology",
              ping_ok(h1, ip_map["h4"]), True)
        check("Routing: h7 ping h4 should benefit from s3-s6 shortcut",
              ping_ok(h7, ip_map["h4"]), True)
        check("Routing: h3 ping h6 through equal-cost/cyclic area",
              ping_ok(h3, ip_map["h6"]), True)
        check("Routing: h1 ping h5 database host by ICMP",
              ping_ok(h1, ip_map["h5"]), True)
        check("Routing: h8 ping h4 from contractor zone",
              ping_ok(h8, ip_map["h4"]), True)

        # Firewall: database isolation.
        check("Firewall deny: h1 client -> h5 database TCP:3306",
              tcp_http_ok(h1, ip_map["h5"], 3306), False)
        check("Firewall deny: h2 client -> h5 database TCP:3306",
              tcp_http_ok(h2, ip_map["h5"], 3306), False)
        check("Firewall deny: h3 guest -> h5 database TCP:3306",
              tcp_http_ok(h3, ip_map["h5"], 3306), False)
        check("Firewall deny: h8 contractor -> h5 database TCP:3306",
              tcp_http_ok(h8, ip_map["h5"], 3306), False)

        # Firewall: allowed DMZ-to-database access.
        check("Firewall allow: h4 web server -> h5 database TCP:3306",
              tcp_http_ok(h4, ip_map["h5"], 3306), True)

        # Firewall: protocol and port specificity.
        check("Firewall deny: h1 -> h4 web TCP:80",
              tcp_http_ok(h1, ip_map["h4"], 80), False)
        check("Firewall allow: h1 -> h4 ICMP still works",
              ping_ok(h1, ip_map["h4"]), True)

        # Firewall: endpoint specificity.
        check("Firewall allow: h2 -> h4 web TCP:80, h1-only rule should not affect h2",
              tcp_http_ok(h2, ip_map["h4"], 80), True)

        # Firewall: admin isolation.
        check("Firewall deny: h3 guest -> h6 admin TCP:22",
              tcp_http_ok(h3, ip_map["h6"], 22), False)
        check("Firewall allow: h1 client -> h6 admin TCP:22",
              tcp_http_ok(h1, ip_map["h6"], 22), True)

        print("==================================")
        print("Summary: %d/%d tests passed" % (passed, total))

        if args.dump_flows:
            dump_flow_evidence(
                net,
                ["s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8"],
                "manual firewall + shortest-path testcase",
            )

        if args.cli:
            print("*** Entering Mininet CLI. Type 'exit' to stop the test.")
            CLI(net)

        return 0 if passed == total else 2

    finally:
        info("*** Cleaning test services\n")
        stop_http_servers(hosts)

        for h in hosts:
            intf = h.defaultIntf().name
            h.cmd("pkill -f 'dhclient.*%s' >/dev/null 2>&1 || true" % intf)

        info("*** Stopping network\n")
        net.stop()


def parse_args():
    parser = argparse.ArgumentParser(
        description="Complex robustness testcase for DHCP, shortest path, and manually configured firewall."
    )
    parser.add_argument("--controller-ip", default="127.0.0.1")
    parser.add_argument("--controller-port", type=int, default=6633)
    parser.add_argument("--initial-wait", type=int, default=5)
    parser.add_argument("--dhcp-timeout", type=int, default=10)
    parser.add_argument(
        "--no-shortest-path-audit",
        dest="shortest_path_audit",
        action="store_false",
        help="Skip ping-based shortest path audit.",
    )
    parser.add_argument(
        "--dump-flows",
        action="store_true",
        help="Dump selected OVS flow tables for report screenshots.",
    )
    parser.add_argument(
        "--cli",
        action="store_true",
        help="Enter Mininet CLI after automated tests.",
    )
    parser.set_defaults(shortest_path_audit=True)
    return parser.parse_args()


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[ERROR] Please run this script with sudo.")
        sys.exit(1)

    setLogLevel("info")
    sys.exit(run_tests(parse_args()))
