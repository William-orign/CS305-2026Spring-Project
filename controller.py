from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import MAIN_DISPATCHER
from os_ken.controller.handler import set_ev_cls
from os_ken.topology import event
from os_ken.ofproto import ofproto_v1_0, ether
from os_ken.lib.packet import packet, ethernet, ether_types, arp
from os_ken.lib.packet import dhcp
from os_ken.lib import hub

from dhcp import DHCPServer
from ofctl_utilis import OfCtl, VLANID_NONE
from firewall import Firewall

from collections import defaultdict
import heapq


class ControllerApp(app_manager.OSKenApp):
    """
    CS305 SDN Controller

    当前实现：
    1. DHCP：
       DHCP 包交给 dhcp.py 里的 DHCPServer 处理。

    2. Shortest Path Switching：
       - 监听 switch / link / host 加入事件；
       - 维护全局拓扑图；
       - 通过 gratuitous ARP 学习 host 的 IP / MAC / 接入 switch / 接入口；
       - 对 ARP request 主动回复 ARP reply，不使用广播；
       - 对 IPv4 packet 根据目的 MAC 计算最短路径，并下发 flow rule。

    3. Bonus：
       支持两种 routing algorithm：
       - Dijkstra
       - Bellman-Ford
    """

    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    # ============================================================
    # Bonus: 在这里切换 routing algorithm
    # ============================================================
    ROUTING_ALGO = "dijkstra"
    # ROUTING_ALGO = "bellman_ford"

    def __init__(self, *args, **kwargs):
        super(ControllerApp, self).__init__(*args, **kwargs)

        # dpid -> datapath
        # datapath 是 os-ken 用来向某个 switch 下发 OpenFlow 消息的对象
        self.switches = {}

        # graph[src_dpid][dst_dpid] = out_port
        # 含义：
        # 如果当前在 src_dpid 这个 switch，
        # 要去相邻 switch dst_dpid，
        # 应该从 out_port 发出去
        self.graph = defaultdict(dict)

        # links[(src_dpid, dst_dpid)] = src_port
        # 记录 switch-switch link 的端口
        self.links = {}

        # mac -> {"ip": ip, "dpid": dpid, "port": port}
        # 记录每个 host 接在哪个 switch 的哪个端口
        self.hosts_by_mac = {}

        # ip -> mac
        # 收到 ARP request 时，用目标 IP 查目标 MAC
        self.ip_to_mac = {}

        # 可选 firewall 模块
        # 现在 switching 测试不依赖 firewall。
        # 如果 firewall.py 还没写完，这里不会影响 shortest path switching。
        try:
            self.firewall = Firewall()
        except Exception as e:
            self.firewall = None
            self.logger.warning("Firewall init failed: %s", e)

        self.firewall_reload_thread = None

        if self.firewall is not None:
            self.firewall_reload_thread = hub.spawn(self._firewall_reload_loop)

        self.logger.info(
            "Controller started. Routing algorithm = %s",
            self.ROUTING_ALGO
        )

    # ============================================================
    # 工具函数：host / topology 学习
    # ============================================================

    def _learn_host(self, mac, ip, dpid, port):
        """
        记录 host 信息。

        mac:
            host 的 MAC 地址

        ip:
            host 的 IP 地址，可以为空

        dpid:
            host 连接的 switch id

        port:
            host 连接的 switch port
        """
        if mac is None:
            return

        # 忽略广播 MAC，不把广播地址当成 host
        if mac == "ff:ff:ff:ff:ff:ff":
            return

        old_info = self.hosts_by_mac.get(mac)

        self.hosts_by_mac[mac] = {
            "ip": ip,
            "dpid": dpid,
            "port": port
        }

        if ip:
            self.ip_to_mac[ip] = mac

        if old_info != self.hosts_by_mac[mac]:
            self.logger.info(
                "[HOST] learn host: mac=%s ip=%s switch=s%s port=%s",
                mac, ip, dpid, port
            )

    def _get_host_ip_from_event(self, host):
        """
        EventHostAdd 里面的 host.ipv4 通常是一个 list。
        这里取第一个 IPv4 地址。
        """
        try:
            if host.ipv4:
                return host.ipv4[0]
        except Exception:
            pass

        return None

    def _install_firewall_on_switch(self, dpid, datapath):
        """
        如果 firewall.py 已经实现，可以在 switch 加入时安装 firewall rules。
        如果 firewall.py 还没实现，self.firewall.rules 为空，不会有影响。
        """
        if self.firewall is None:
            return

        try:
            self.firewall.clear_installed_for_switch(dpid)#在安装前先清除之前安装的规则的记录，避免再加入时不装
            ofctl = OfCtl.factory(datapath, self.logger)
            self.firewall.install_rules({dpid: ofctl})
        except Exception as e:
            self.logger.warning(
                "[FIREWALL] install rules failed on s%s: %s",
                dpid, e
            )
    
    def _build_firewall_ofctls(self):
        """
        Build OfCtl objects for all currently connected switches.
        """
        ofctls = {}

        for dpid, datapath in list(self.switches.items()):
            try:
                ofctls[dpid] = OfCtl.factory(datapath, self.logger)
            except Exception as e:
                self.logger.warning(
                    "[FIREWALL] cannot create OfCtl for s%s: %s",
                    dpid,
                    e
                )

        return ofctls

    def _firewall_reload_loop(self):
        """
        Periodically check whether firewall_rule.json has changed.
        If changed, reload firewall rules without restarting controller or Mininet.
        """
        self.logger.info(
            "[FIREWALL] reload watcher started, rule_file=%s",
            self.firewall.rule_file
        )
        
        while True:
            hub.sleep(1)

            if self.firewall is None:
                continue

            try:
                if not self.firewall.rule_file_changed():
                    continue

                ofctls = self._build_firewall_ofctls()

                if not ofctls:
                    self.firewall.mark_rule_file_seen()
                    continue

                self.logger.info("[FIREWALL] rule file changed, reloading...")

                self.firewall.reload_rules(ofctls)

                self.logger.info("[FIREWALL] dynamic reload completed")

            except Exception as e:
                self.logger.warning("[FIREWALL] dynamic reload failed: %s", e)
                if self.firewall is not None:
                    self.firewall.mark_rule_file_seen()

    
    def _print_topology_and_all_paths(self, reason=""):
        """
        Print the current topology and the shortest paths between every pair
        of switches.

        This is mainly for the project demo requirement:
        after each topology change, the controller should show the current
        topology structure and the shortest path between any two switches.
        """
        switches = sorted(set(self.switches.keys()) | set(self.graph.keys()))

        self.logger.info(
            "========== TOPOLOGY UPDATE: %s ==========",
            reason
        )

        if not switches:
            self.logger.info("[TOPOLOGY] no switch in current topology")
            self.logger.info("================================================")
            return

        # 1. Print all switches.
        self.logger.info(
            "[TOPOLOGY] switches: %s",
            ", ".join(["s%s" % dpid for dpid in switches])
        )

        # 2. Print all switch-switch links.
        self.logger.info("[TOPOLOGY] links:")

        has_link = False

        for src in switches:
            for dst, src_port in sorted(self.graph.get(src, {}).items()):
                # Avoid duplicate printing for undirected links.
                # For example, print s1-s2 only once instead of printing
                # both s1-s2 and s2-s1.
                if src < dst:
                    dst_port = self.graph.get(dst, {}).get(src)
                    self.logger.info(
                        "    s%s:%s <--> s%s:%s",
                        src, src_port, dst, dst_port
                    )
                    has_link = True

        if not has_link:
            self.logger.info("    none")

        # 3. Print shortest paths between every pair of switches.
        self.logger.info(
            "[ALL-PAIRS SHORTEST PATHS] algorithm=%s",
            self.ROUTING_ALGO
        )

        if len(switches) < 2:
            self.logger.info("    only one switch, no switch-pair path")
            self.logger.info("================================================")
            return

        for i in range(len(switches)):
            for j in range(i + 1, len(switches)):
                src = switches[i]
                dst = switches[j]

                path = self._shortest_path(src, dst)

                if path is None:
                    self.logger.info(
                        "    s%s -> s%s: no path",
                        src, dst
                    )
                else:
                    path_str = " -> ".join(["s%s" % dpid for dpid in path])
                    self.logger.info(
                        "    s%s -> s%s: %s, length=%d",
                        src, dst, path_str, len(path) - 1
                    )

        self.logger.info("================================================")

    def _remove_links_by_port(self, dpid, port_no):
        """
        Remove switch-switch links that use the specified switch port.
        This is used when a port becomes down.
        """
        removed_neighbors = []

        for (src, dst), out_port in list(self.links.items()):
            if src == dpid and out_port == port_no:
                removed_neighbors.append(dst)

        for dst in removed_neighbors:
            self.links.pop((dpid, dst), None)
            self.links.pop((dst, dpid), None)

            if dpid in self.graph:
                self.graph[dpid].pop(dst, None)

            if dst in self.graph:
                self.graph[dst].pop(dpid, None)

            self.logger.info(
                "[PORT] related link removed from graph: s%s <--> s%s",
                dpid, dst
            )

    # ============================================================
    # Topology Event Handlers
    # ============================================================

    @set_ev_cls(event.EventSwitchEnter)
    def handle_switch_add(self, ev):
        """
        当 switch 加入网络时触发。

        我们需要保存 datapath，
        因为之后下发 flow rule 要用它。
        """
        sw = ev.switch
        datapath = sw.dp
        dpid = datapath.id

        self.switches[dpid] = datapath

        # 初始化 graph 里的节点
        # 即使暂时没有边，也要记录这个 switch
        if dpid not in self.graph:
            self.graph[dpid] = {}

        self.logger.info("[SWITCH] s%s joined", dpid)

        # 如果 firewall 已经实现，可以顺手给新 switch 安装 firewall rules
        self._install_firewall_on_switch(dpid, datapath)

        self._print_topology_and_all_paths("switch s%s joined" % dpid)

    @set_ev_cls(event.EventSwitchLeave)
    def handle_switch_delete(self, ev):
        """
        当 switch 离开网络时触发。
        删除该 switch 以及和它相关的所有边。
        """
        sw = ev.switch
        dpid = sw.dp.id

        self.switches.pop(dpid, None)
        self.graph.pop(dpid, None)

        # 删除其他 switch 指向该 switch 的边
        for src in list(self.graph.keys()):
            self.graph[src].pop(dpid, None)

        # 删除 links 中相关记录
        for key in list(self.links.keys()):
            if key[0] == dpid or key[1] == dpid:
                self.links.pop(key, None)

        self.logger.info("[SWITCH] s%s left", dpid)

        self._print_topology_and_all_paths("switch s%s left" % dpid)

    @set_ev_cls(event.EventHostAdd)
    def handle_host_add(self, ev):
        """
        当 controller 发现 host 时触发。

        README 里说测试脚本会让 host 发送 arping / gratuitous ARP。
        os-ken topology 模块可能因此产生 EventHostAdd。

        为了更稳，我们在 packet_in_handler 里也会从 ARP 包学习 host。
        """
        host = ev.host
        mac = host.mac
        ip = self._get_host_ip_from_event(host)

        # host.port 里面记录了 host 接入的 switch 和 port
        dpid = host.port.dpid
        port_no = host.port.port_no

        self._learn_host(mac, ip, dpid, port_no)

    @set_ev_cls(event.EventLinkAdd)
    def handle_link_add(self, ev):
        """
        当两个 switch 之间出现 link 时触发。

        link.src:
            src.dpid    源 switch id
            src.port_no 从源 switch 出去的端口

        link.dst:
            dst.dpid    目标 switch id
            dst.port_no 从目标 switch 回来的端口

        对于无向链路，我们同时记录两个方向：
            src -> dst
            dst -> src
        """
        link = ev.link

        src_dpid = link.src.dpid
        dst_dpid = link.dst.dpid
        src_port = link.src.port_no
        dst_port = link.dst.port_no

        self.links[(src_dpid, dst_dpid)] = src_port
        self.links[(dst_dpid, src_dpid)] = dst_port

        self.graph[src_dpid][dst_dpid] = src_port
        self.graph[dst_dpid][src_dpid] = dst_port

        self.logger.info(
            "[LINK] s%s:%s <--> s%s:%s",
            src_dpid, src_port, dst_dpid, dst_port
        )

        self._print_topology_and_all_paths(
            "link s%s-s%s added" % (src_dpid, dst_dpid)
        )

    @set_ev_cls(event.EventLinkDelete)
    def handle_link_delete(self, ev):
        """
        当 switch-switch link 被删除时触发。
        删除内部拓扑图中的对应边。

        说明：
        这里会更新 controller 的拓扑图。
        已经安装在 switch 里的旧 flow rule 不一定会立刻删除。
        但是新的 PacketIn 会根据新拓扑重新计算路径。

        基础 switching_test 不会动态删除链路，
        所以这已经够跑基础测试。
        """
        link = ev.link

        src_dpid = link.src.dpid
        dst_dpid = link.dst.dpid

        self.links.pop((src_dpid, dst_dpid), None)
        self.links.pop((dst_dpid, src_dpid), None)

        if src_dpid in self.graph:
            self.graph[src_dpid].pop(dst_dpid, None)

        if dst_dpid in self.graph:
            self.graph[dst_dpid].pop(src_dpid, None)

        self.logger.info(
            "[LINK] removed: s%s <--> s%s",
            src_dpid, dst_dpid
        )

        self._print_topology_and_all_paths(
            "link s%s-s%s removed" % (src_dpid, dst_dpid)
        )

    @set_ev_cls(event.EventPortModify)
    def handle_port_modify(self, ev):
        """
        当 switch port 状态变化时触发。

        如果 port down，并且该 port 是 switch-switch link 的端口，
        就从 self.graph 和 self.links 中删除对应边。
        最后打印当前拓扑和所有 switch-pair shortest paths。
        """
        port = ev.port
        dpid = port.dpid
        port_no = port.port_no

        self.logger.info(
            "[PORT] modified: switch=s%s port=%s",
            dpid, port_no
        )

        is_down = False

        try:
            if hasattr(port, "state"):
                is_down = bool(port.state & ofproto_v1_0.OFPPS_LINK_DOWN)
        except Exception:
            is_down = False

        if is_down:
            self._remove_links_by_port(dpid, port_no)

        self._print_topology_and_all_paths(
            "port modified on s%s:%s" % (dpid, port_no)
        )

    # ============================================================
    # Shortest Path Algorithms
    # ============================================================

    def _shortest_path(self, src_dpid, dst_dpid):
        """
        根据 ROUTING_ALGO 选择具体算法。

        返回值是 switch dpid 列表，例如：
            [1, 2, 3]

        表示路径：
            s1 -> s2 -> s3
        """
        if src_dpid == dst_dpid:
            return [src_dpid]

        if self.ROUTING_ALGO == "bellman_ford":
            return self._bellman_ford(src_dpid, dst_dpid)

        # 默认使用 Dijkstra
        return self._dijkstra(src_dpid, dst_dpid)

    def _dijkstra(self, src, dst):
        """
        Dijkstra 最短路径算法。

        本项目的 link 没有复杂权重，
        所以每条 switch-switch link 的 cost 都是 1。

        因此算出来的就是经过 switch 数量最少的路径。
        """
        dist = defaultdict(lambda: float("inf"))
        prev = {}

        dist[src] = 0

        # heap 元素：(当前距离, 当前节点)
        heap = [(0, src)]
        visited = set()

        while heap:
            cur_dist, u = heapq.heappop(heap)

            if u in visited:
                continue

            visited.add(u)

            if u == dst:
                break

            # sorted 是为了路径选择更稳定，方便 demo 和 debug
            for v in sorted(self.graph.get(u, {}).keys()):
                if v in visited:
                    continue

                new_dist = cur_dist + 1

                if new_dist < dist[v]:
                    dist[v] = new_dist
                    prev[v] = u
                    heapq.heappush(heap, (new_dist, v))

        if dst not in prev and src != dst:
            return None

        return self._reconstruct_path(src, dst, prev)

    def _bellman_ford(self, src, dst):
        """
        Bellman-Ford 最短路径算法。

        本项目中边权都是 1，
        所以它和 Dijkstra 的结果通常一样。

        但实现这个算法可以作为 bonus：
        different routing algorithms。
        """
        nodes = set(self.graph.keys())

        for u in self.graph:
            for v in self.graph[u]:
                nodes.add(v)

        dist = {node: float("inf") for node in nodes}
        prev = {}

        dist[src] = 0

        # 构造有向边列表。
        # 因为 graph 已经记录了两个方向，所以这里直接遍历即可。
        edges = []

        for u in self.graph:
            for v in self.graph[u]:
                edges.append((u, v, 1))

        # Bellman-Ford 核心：最多松弛 |V|-1 次
        for _ in range(max(len(nodes) - 1, 0)):
            updated = False

            for u, v, w in edges:
                if dist.get(u, float("inf")) + w < dist.get(v, float("inf")):
                    dist[v] = dist[u] + w
                    prev[v] = u
                    updated = True

            # 如果本轮没有更新，说明已经收敛，可以提前停止
            if not updated:
                break

        if dst not in prev and src != dst:
            return None

        return self._reconstruct_path(src, dst, prev)

    def _reconstruct_path(self, src, dst, prev):
        """
        根据 prev 字典恢复路径。
        """
        path = [dst]
        cur = dst

        while cur != src:
            if cur not in prev:
                return None

            cur = prev[cur]
            path.append(cur)

        path.reverse()
        return path

    # ============================================================
    # Flow Rule Installation
    # ============================================================

    def _add_forwarding_rule(self, datapath, dst_mac, out_port):
        """
        给某个 switch 下发一条 forwarding rule。

        匹配条件：
            dl_type = IPv4
            dl_dst  = 目的 MAC 地址

        动作：
            output 到 out_port
        """
        ofctl = OfCtl.factory(datapath, self.logger)

        actions = [
            datapath.ofproto_parser.OFPActionOutput(out_port, 0)
        ]

        ofctl.set_flow(
            cookie=0,
            priority=100,
            dl_type=ether.ETH_TYPE_IP,
            dl_vlan=VLANID_NONE,
            dl_dst=dst_mac,
            actions=actions
        )

        self.logger.info(
            "[FLOW] install on s%s: dst_mac=%s -> out_port=%s",
            datapath.id, dst_mac, out_port
        )

    def _install_path_rules(self, path, dst_mac, dst_host):
        """
        在路径上的每个 switch 安装到 dst_mac 的 flow rule。

        path:
            [s1, s2, s3]

        如果当前 switch 不是最后一个：
            output port = 到下一个 switch 的端口

        如果当前 switch 是最后一个：
            output port = 目标 host 接入端口
        """
        if not path:
            return

        for i, cur_dpid in enumerate(path):
            datapath = self.switches.get(cur_dpid)

            if datapath is None:
                continue

            if i == len(path) - 1:
                # 最后一个 switch：直接发给目标 host
                out_port = dst_host["port"]
            else:
                # 中间 switch：发给路径上的下一个 switch
                next_dpid = path[i + 1]
                out_port = self.graph[cur_dpid].get(next_dpid)

            if out_port is None:
                self.logger.warning(
                    "[FLOW] cannot find out_port: s%s path=%s",
                    cur_dpid, path
                )
                return

            self._add_forwarding_rule(datapath, dst_mac, out_port)

    def _print_path(self, src_mac, dst_mac, path):
        """
        按 README 要求，在 controller 端显示 shortest path。
        """
        src_host = self.hosts_by_mac.get(src_mac)
        dst_host = self.hosts_by_mac.get(dst_mac)

        if src_host is None or dst_host is None or path is None:
            return

        src_ip = src_host.get("ip")
        dst_ip = dst_host.get("ip")

        switch_path = ["s%s" % dpid for dpid in path]
        full_path = ["host(%s)" % src_ip] + switch_path + ["host(%s)" % dst_ip]

        self.logger.info(
            "[PATH] %s(%s) -> %s(%s): %s, distance=%d, algorithm=%s",
            src_ip,
            src_mac,
            dst_ip,
            dst_mac,
            " -> ".join(full_path),
            len(full_path) - 1,
            self.ROUTING_ALGO
        )

    def _packet_out(self, datapath, in_port, out_port, data):
        """
        把当前这个 PacketIn 的 packet 立刻从指定端口发出去。

        为什么需要这个？
        因为 flow rule 是给“之后的包”用的；
        当前这个已经到 controller 的包，需要 PacketOut 才能继续转发。
        """
        actions = [
            datapath.ofproto_parser.OFPActionOutput(out_port, 0)
        ]

        datapath.send_packet_out(
            buffer_id=0xffffffff,
            in_port=in_port,
            actions=actions,
            data=data
        )

    def _get_out_port_on_path(self, cur_dpid, path, dst_host):
        """
        给当前 switch 找输出端口。
        """
        if path is None or cur_dpid not in path:
            return None

        index = path.index(cur_dpid)

        if index == len(path) - 1:
            return dst_host["port"]

        next_dpid = path[index + 1]
        return self.graph[cur_dpid].get(next_dpid)

    # ============================================================
    # ARP Handling
    # ============================================================

    def _handle_arp(self, datapath, in_port, pkt, eth_pkt, arp_pkt):
        """
        处理 ARP packet。

        分两种情况：

        1. Gratuitous ARP / ARP reply:
           用来学习 host 的 IP 和 MAC。

        2. ARP request:
           host 想知道某个 IP 对应的 MAC。
           controller 查询 ip_to_mac，然后主动回复 ARP reply。
        """
        dpid = datapath.id

        # 不管是 ARP request 还是 reply，都先学习发送者
        self._learn_host(
            mac=arp_pkt.src_mac,
            ip=arp_pkt.src_ip,
            dpid=dpid,
            port=in_port
        )

        # 处理 ARP request：Who has dst_ip?
        if arp_pkt.opcode == arp.ARP_REQUEST:
            target_ip = arp_pkt.dst_ip
            target_mac = self.ip_to_mac.get(target_ip)

            if target_mac is None:
                self.logger.info(
                    "[ARP] unknown target ip=%s, cannot reply now",
                    target_ip
                )
                return

            ofctl = OfCtl.factory(datapath, self.logger)

            # 构造 ARP reply：
            # 告诉请求者：target_ip 的 MAC 是 target_mac
            ofctl.send_arp(
                arp_opcode=arp.ARP_REPLY,
                vlan_id=VLANID_NONE,
                dst_mac=arp_pkt.src_mac,
                sender_mac=target_mac,
                sender_ip=target_ip,
                target_ip=arp_pkt.src_ip,
                target_mac=arp_pkt.src_mac,
                src_port=datapath.ofproto.OFPP_CONTROLLER,
                output_port=in_port
            )

            self.logger.info(
                "[ARP] reply: %s is at %s, send to %s via s%s:%s",
                target_ip, target_mac, arp_pkt.src_mac, dpid, in_port
            )

        elif arp_pkt.opcode == arp.ARP_REPLY:
            # Gratuitous ARP 通常会走到这里。
            # 学习动作前面已经做了，所以这里只打印。
            self.logger.info(
                "[ARP] learn from ARP_REPLY: %s is at %s",
                arp_pkt.src_ip, arp_pkt.src_mac
            )

    # ============================================================
    # IPv4 Handling
    # ============================================================

    def _handle_ipv4(self, msg, datapath, in_port, pkt, eth_pkt):
        """
        处理 IPv4 packet。

        核心逻辑：
        1. 根据 Ethernet destination MAC 找目标 host。
        2. 根据源 host 和目标 host 的接入 switch 计算最短路径。
        3. 给路径上的 switch 安装 flow rule。
        4. 把当前 packet 用 PacketOut 发出去。
        """
        src_mac = eth_pkt.src
        dst_mac = eth_pkt.dst

        src_host = self.hosts_by_mac.get(src_mac)
        dst_host = self.hosts_by_mac.get(dst_mac)

        if dst_host is None:
            self.logger.info(
                "[IPv4] unknown dst_mac=%s, ignore packet",
                dst_mac
            )
            return

        # 如果源 host 还没被记录，至少记录它当前所在位置。
        # IP 可以为空，不影响按 MAC 转发。
        if src_host is None:
            self._learn_host(src_mac, None, datapath.id, in_port)
            src_host = self.hosts_by_mac.get(src_mac)

        src_dpid = src_host["dpid"]
        dst_dpid = dst_host["dpid"]

        path = self._shortest_path(src_dpid, dst_dpid)

        if path is None:
            self.logger.warning(
                "[PATH] no path from s%s to s%s for %s -> %s",
                src_dpid, dst_dpid, src_mac, dst_mac
            )
            return

        # 安装正向路径：src -> dst
        self._install_path_rules(path, dst_mac, dst_host)
        self._print_path(src_mac, dst_mac, path)

        # 顺手安装反向路径：dst -> src
        # ping 回复包需要反方向；
        # 提前安装可以减少 PacketIn 次数。
        if src_host is not None:
            reverse_path = list(reversed(path))
            self._install_path_rules(reverse_path, src_mac, src_host)
            self._print_path(dst_mac, src_mac, reverse_path)

        # 把当前 packet 发出去
        out_port = self._get_out_port_on_path(
            datapath.id,
            path,
            dst_host
        )

        if out_port is None:
            # 如果当前 switch 不在 src->dst 的完整路径上，
            # 就从当前 switch 到目的 switch 单独算一条路径。
            current_path = self._shortest_path(datapath.id, dst_dpid)
            out_port = self._get_out_port_on_path(
                datapath.id,
                current_path,
                dst_host
            )

        if out_port is None:
            self.logger.warning(
                "[PacketOut] cannot decide out_port on s%s for dst=%s",
                datapath.id, dst_mac
            )
            return

        self._packet_out(datapath, in_port, out_port, msg.data)

    # ============================================================
    # Main PacketIn Handler
    # ============================================================

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """
        switch 把无法处理的 packet 交给 controller 时，会进入这里。

        按协议分流：
        1. DHCP -> 交给 DHCPServer
        2. ARP  -> 学习 host / 回复 ARP request
        3. IPv4 -> shortest path switching
        4. 其他 -> 忽略
        """
        try:
            msg = ev.msg
            datapath = msg.datapath
            in_port = msg.in_port

            pkt = packet.Packet(data=msg.data)

            eth_pkt = pkt.get_protocol(ethernet.ethernet)

            if eth_pkt is None:
                return

            # 忽略 LLDP。
            # os-ken 用 LLDP 发现拓扑，不应该拿来当普通流量处理。
            if eth_pkt.ethertype == ether_types.ETH_TYPE_LLDP:
                return

            # 1. DHCP
            pkt_dhcp = pkt.get_protocols(dhcp.dhcp)

            if pkt_dhcp:
                DHCPServer.handle_dhcp(datapath, in_port, pkt)
                return

            # 2. ARP
            arp_pkt = pkt.get_protocol(arp.arp)

            if arp_pkt:
                self._handle_arp(
                    datapath,
                    in_port,
                    pkt,
                    eth_pkt,
                    arp_pkt
                )
                return

            # 3. IPv4
            if eth_pkt.ethertype == ether_types.ETH_TYPE_IP:
                self._handle_ipv4(
                    msg,
                    datapath,
                    in_port,
                    pkt,
                    eth_pkt
                )
                return

            # 4. 其他包暂时不处理
            self.logger.debug(
                "[PacketIn] ignore ethertype=0x%04x on s%s port=%s",
                eth_pkt.ethertype, datapath.id, in_port
            )

        except Exception as e:
            self.logger.exception(
                "[ERROR] packet_in_handler failed: %s",
                e
            )
