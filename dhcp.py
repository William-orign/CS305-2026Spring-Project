from os_ken.lib import addrconv
from os_ken.lib.packet import packet, ethernet, ipv4, udp, dhcp
from os_ken.ofproto import inet
from os_ken.lib.packet import ether_types
import ipaddress
import logging


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

    allocated_ips = {}
    _logger = logging.getLogger(__name__)

    @classmethod
    def assemble_dhcp_reply(cls, pkt, assigned_ip, msg_type):
        """
        统一构建 DHCP 回复包 (OFFER 或 ACK)
        """
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        dhcp_pkt = pkt.get_protocol(dhcp.dhcp)

        client_mac = eth_pkt.src

        # 1. 封装 Ethernet 层
        eth = ethernet.ethernet(dst=client_mac,
                    src=cls.hardware_addr,
                    ethertype=ether_types.ETH_TYPE_IP)

        # 2. 封装 IPv4 层 (DHCP 回复通常以广播形式发送给客户端)
        ip = ipv4.ipv4(src=cls.server_ip,
                       dst='255.255.255.255',
                       proto=inet.IPPROTO_UDP)

        # 3. 封装 UDP 层 (Server 端口 67, Client 端口 68)
        u = udp.udp(src_port=67, dst_port=68)

        # 4. 封装 DHCP 层
        # 组装 DHCP 选项 (Message Type 必须有，子网掩码、Server ID、DNS 等)
        options = dhcp.options([
            dhcp.option(tag=dhcp.DHCP_MESSAGE_TYPE_OPT, value=bytes([msg_type])),
            dhcp.option(tag=dhcp.DHCP_SUBNET_MASK_OPT, value=addrconv.ipv4.text_to_bin(cls.netmask)),
            dhcp.option(tag=dhcp.DHCP_SERVER_IDENTIFIER_OPT, value=addrconv.ipv4.text_to_bin(cls.server_ip)),
            # 替换为正确的常量名，或者直接用数字 6 也可以：dhcp.option(tag=6, ...)
            dhcp.option(tag=dhcp.DHCP_DOMAIN_NAME_SERVER_OPT, value=addrconv.ipv4.text_to_bin(cls.dns)),
            dhcp.option(tag=dhcp.DHCP_IP_ADDR_LEASE_TIME_OPT, value=b'\xff\xff\xff\xff')  
        ])
        # 补齐 chaddr (Client Hardware Address) 字段到 16 字节
        mac_bin = addrconv.mac.text_to_bin(client_mac)
        chaddr = mac_bin + b'\x00' * 10

        d = dhcp.dhcp(op=dhcp.DHCP_BOOT_REPLY,
                  htype=1,
                  hlen=6,
                  xid=dhcp_pkt.xid,  # 必须和请求的 Transaction ID 保持一致
                  yiaddr=str(assigned_ip),  # 给客户端分配的 IP (Your IP)
                  siaddr=cls.server_ip,  # 下一个 Server 的 IP
                  chaddr=chaddr,
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

        cls._logger.debug("[DHCP DEBUG] 捕捉到来自 %s 的 DHCP 报文，正在解析...", client_mac)

        # 解析 DHCP Message Type，增强兼容性
        msg_type = None
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
                if tag != dhcp.DHCP_MESSAGE_TYPE_OPT:
                    continue
                val = getattr(opt, 'value', None)
                if val is None:
                    continue
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
            except Exception:
                continue

        # 1. 如果是 DHCP DISCOVER，分配 IP 并回复 DHCP OFFER
        if msg_type == dhcp.DHCP_DISCOVER:
            if client_mac not in cls.allocated_ips:
                if cls.ip_pool:
                    cls.allocated_ips[client_mac] = cls.ip_pool.pop(0)
                else:
                    cls._logger.error("[DHCP ERROR] 地址池空了！无法为 %s 分配！", client_mac)
                    return  # 地址池空了，直接忽略
            assigned_ip = cls.allocated_ips[client_mac]
            cls._logger.info("[DHCP SUCCESS] 收到 DISCOVER！正在给 %s 发送 OFFER: %s", client_mac, assigned_ip)

            offer_pkt = cls.assemble_dhcp_reply(pkt, assigned_ip, dhcp.DHCP_OFFER)
            cls._send_packet(datapath, port, offer_pkt)

        # 2. 如果是 DHCP REQUEST，确认分配并回复 DHCP ACK
        elif msg_type == dhcp.DHCP_REQUEST:
            assigned_ip = cls.allocated_ips.get(client_mac)
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