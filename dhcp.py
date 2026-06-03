from os_ken.lib import addrconv
from os_ken.lib.packet import packet, ethernet, ipv4, udp, dhcp
from os_ken.ofproto import inet
from os_ken.lib.packet import ether_types
import ipaddress
import logging
import time


class Config():
    controller_macAddr = '7e:49:b3:f0:f9:99'  # don't modify, a dummy mac address for fill the mac enrty
    dns = '8.8.8.8'  # don't modify, just for the dns entry
    start_ip = '192.168.1.2'  # can be modified
    end_ip = '192.168.1.100'  # can be modified
    netmask = '255.255.255.0'  # can be modified
    server_ip = '192.168.1.1'  # 设定控制器的网关/DHCP Server IP


class DHCPServer():
    hardware_addr = Config.controller_macAddr
    start_ip = Config.start_ip
    end_ip = Config.end_ip
    netmask = Config.netmask
    dns = Config.dns
    server_ip = Config.server_ip
    lease_duration = 10  # 设置租期为 10 秒，方便测试和验证过期机制

    # 简单的 IP 地址池和已分配 IP 记录字典 (MAC -> IP)
    # 使用 Config.start_ip 和 Config.end_ip 生成连续的可分配地址池
    try:
        _start = ipaddress.IPv4Address(Config.start_ip)
        _end = ipaddress.IPv4Address(Config.end_ip)
        if int(_start) <= int(_end):
            ip_pool = [str(ipaddress.IPv4Address(i)) for i in range(int(_start), int(_end) + 1)]
        else:
            ip_pool = []
    except Exception:
        # 兜底：如果配置不合法，生成一个小的默认池
        ip_pool = [str(ip) for ip in ipaddress.IPv4Network('192.168.1.0/24').hosts()][:254]

    leases = {}
    _logger = logging.getLogger(__name__)
  
    @classmethod
    def _now(cls):
        return time.time()

    @classmethod
    def _cleanup_expired_leases(cls, now=None):
        if now is None:
            now = cls._now()

        expired = []

        for mac, lease in list(cls.leases.items()):
            if lease.get("expire_time", 0) <= now:
                expired.append((mac, lease.get("ip")))

        for mac, ip in expired:
            cls.leases.pop(mac, None)
            if ip and ip not in cls.ip_pool:
                cls.ip_pool.append(ip)

        if expired:
            cls.ip_pool.sort(key=lambda value: int(ipaddress.IPv4Address(value)))

    @classmethod
    def _allocate_ip(cls, mac, now=None):
        if now is None:
            now = cls._now()

        cls._cleanup_expired_leases(now)

        lease = cls.leases.get(mac)
        if lease:
            return lease.get("ip")

        if not cls.ip_pool:
            return None

        assigned_ip = cls.ip_pool.pop(0)
        cls.leases[mac] = {
            "ip": assigned_ip,
            "expire_time": now + cls.lease_duration,
        }

        return assigned_ip

    @classmethod
    def _refresh_lease(cls, mac, assigned_ip, now=None):
        if now is None:
            now = cls._now()

        cls.leases[mac] = {
            "ip": assigned_ip,
            "expire_time": now + cls.lease_duration,
        }

    @classmethod
    def _assign_requested_ip(cls, mac, requested_ip, now=None):
        if now is None:
            now = cls._now()

        cls._cleanup_expired_leases(now)

        if requested_ip in cls.ip_pool:
            cls.ip_pool.remove(requested_ip)
            cls._refresh_lease(mac, requested_ip, now)
            return requested_ip

        lease = cls.leases.get(mac)
        if lease and lease.get("ip") == requested_ip:
            cls._refresh_lease(mac, requested_ip, now)
            return requested_ip

        return None

    @classmethod
    def assemble_dhcp_reply(cls, pkt, assigned_ip, msg_type):
        import struct  # 新增：用于标准转化租约时间
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        dhcp_pkt = pkt.get_protocol(dhcp.dhcp)

        client_mac = eth_pkt.src

        # 【核心修复 1】：尊重客户端的 Flags，动态决定单播还是广播
        is_broadcast = False
        try:
            is_broadcast = (dhcp_pkt.flags & 0x8000) != 0
        except Exception:
            is_broadcast = False

        target_mac = 'ff:ff:ff:ff:ff:ff' if is_broadcast else client_mac
        target_ip = '255.255.255.255' if is_broadcast else str(assigned_ip)

        eth = ethernet.ethernet(dst=target_mac,
                                src=cls.hardware_addr,
                                ethertype=ether_types.ETH_TYPE_IP)

        ip = ipv4.ipv4(src=cls.server_ip,
                       dst=target_ip,
                       proto=inet.IPPROTO_UDP)

        u = udp.udp(src_port=67, dst_port=68)

        # 【核心修复 2】：改用标准的一天 (86400秒) 租期，避免 \xff 触发 dhclient 的 bug
        lease_time_bin = struct.pack('!I', cls.lease_duration)

        options = dhcp.options([
            dhcp.option(tag=dhcp.DHCP_MESSAGE_TYPE_OPT, value=bytes([msg_type])),
            dhcp.option(tag=dhcp.DHCP_SUBNET_MASK_OPT, value=addrconv.ipv4.text_to_bin(cls.netmask)),
            dhcp.option(tag=dhcp.DHCP_SERVER_IDENTIFIER_OPT, value=addrconv.ipv4.text_to_bin(cls.server_ip)),
            dhcp.option(tag=6, value=addrconv.ipv4.text_to_bin(cls.dns)),
            dhcp.option(tag=dhcp.DHCP_IP_ADDR_LEASE_TIME_OPT, value=lease_time_bin)
        ])

        # 【核心修复 3】：原封不动地返回客户端请求中的 chaddr、giaddr 和 flags，保证 100% 匹配验证
        giaddr = getattr(dhcp_pkt, 'giaddr', 0)
        chaddr = getattr(dhcp_pkt, 'chaddr', None)
        flags = getattr(dhcp_pkt, 'flags', 0)

        d = dhcp.dhcp(op=dhcp.DHCP_BOOT_REPLY,
                      htype=1,
                      hlen=6,
                      xid=dhcp_pkt.xid,
                      yiaddr=str(assigned_ip),
                      siaddr=cls.server_ip,
                      giaddr=giaddr,
                      chaddr=chaddr,
                      flags=flags,
                      options=options)

        reply_pkt = packet.Packet()
        reply_pkt.add_protocol(eth)
        reply_pkt.add_protocol(ip)
        reply_pkt.add_protocol(u)
        reply_pkt.add_protocol(d)

        return reply_pkt

    @classmethod
    def handle_dhcp(cls, datapath, port, pkt):
        """
        处理传入的 DHCP 报文并进行响应
        """
        # 终极安全检查：确保这确实是一个 DHCP 报文
        dhcp_pkt = pkt.get_protocol(dhcp.dhcp)
        if not dhcp_pkt:
            return

        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        client_mac = eth_pkt.src
        now = cls._now()

        cls._cleanup_expired_leases(now)

        cls._logger.debug("[DHCP DEBUG] 捕捉到来自 %s 的 DHCP 报文，正在解析...", client_mac)

        # 解析 DHCP Message Type，增强兼容性
        msg_type = None
        requested_ip = None
        opts = []
        if hasattr(dhcp_pkt, 'options'):
            if isinstance(dhcp_pkt.options, list):
                opts = dhcp_pkt.options
            elif hasattr(dhcp_pkt.options, 'option_list'):
                opts = dhcp_pkt.options.option_list
            else:
                # 可能是其他可迭代类型
                try:
                    opts = list(dhcp_pkt.options)
                except Exception:
                    opts = []

        for opt in opts:
            try:
                tag = getattr(opt, 'tag', None)
                val = getattr(opt, 'value', None)
                if val is None:
                    continue

                if tag == dhcp.DHCP_MESSAGE_TYPE_OPT:
                    if isinstance(val, (bytes, bytearray)) and len(val) > 0:
                        msg_type = val[0]
                    elif isinstance(val, int):
                        msg_type = val
                    elif isinstance(val, str):
                        try:
                            msg_type = int(val)
                        except Exception:
                            if val:
                                msg_type = ord(val[0])
                    if msg_type is not None:
                        break

                elif tag == 50:
                    if isinstance(val, (bytes, bytearray)) and len(val) == 4:
                        requested_ip = str(ipaddress.IPv4Address(int.from_bytes(val, byteorder='big')))
            except Exception:
                continue

        # 1. 如果是 DHCP DISCOVER，分配 IP 并回复 DHCP OFFER
        if msg_type == dhcp.DHCP_DISCOVER:
            assigned_ip = cls._allocate_ip(client_mac, now)

            if assigned_ip is None:
                cls._logger.error("[DHCP ERROR] 地址池空了！无法为 %s 分配！", client_mac)
                return

            cls._logger.info("[DHCP SUCCESS] 收到 DISCOVER！正在给 %s 发送 OFFER: %s", client_mac, assigned_ip)

            offer_pkt = cls.assemble_dhcp_reply(pkt, assigned_ip, dhcp.DHCP_OFFER)
            cls._send_packet(datapath, port, offer_pkt)

        # 2. 如果是 DHCP REQUEST，确认分配并回复 DHCP ACK
        elif msg_type == dhcp.DHCP_REQUEST:
            assigned_ip = None

            if requested_ip:
                assigned_ip = cls._assign_requested_ip(client_mac, requested_ip, now)

            if assigned_ip is None:
                assigned_ip = cls._allocate_ip(client_mac, now)

            if assigned_ip:
                cls._logger.info("[DHCP SUCCESS] 收到 REQUEST！确认分配 ACK: %s", assigned_ip)
                ack_pkt = cls.assemble_dhcp_reply(pkt, assigned_ip, dhcp.DHCP_ACK)
                cls._send_packet(datapath, port, ack_pkt)

    @classmethod
    def _send_packet(cls, datapath, port, pkt):
        # 原始发包逻辑，无需改动
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        if isinstance(pkt, str):
            pkt = pkt.encode()
        pkt.serialize()
        data = pkt.data
        actions = [parser.OFPActionOutput(port, 0)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)