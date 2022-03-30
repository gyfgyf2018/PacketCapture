#include "packanalyzer.h"

QMutex l_packet;
QVector<Result *> resultList;

Result::Result(pcap_pkthdr *h, u_char *d) : header(h), data(d), info("") {}

void Result::getInfo() { info = analyze_MAC(data, header->caplen); }

PackAnalyzer::PackAnalyzer(QObject *parent) : QObject{parent} {}

void PackAnalyzer::run() {
  int i = 0, len;
  Result *res;
  do {
    i++;
    l_packet.lock();
    len = resultList.size();
    while (i >= len) {
      l_packet.unlock();
      QThread::msleep(200);
      l_packet.lock();
      len = resultList.size();
    }
    res = resultList[i];
    l_packet.unlock();
    res->getInfo();
    emit analyzed(res);
  } while (running || i < len);
}

QString Result::analyze_MAC(void *data, int size) {
  QString res, s, d;
  MAC *h = (MAC *)data;
  void *next_header = (u_int8_t *)data + sizeof(MAC);
  int next_size = size - sizeof(MAC);

  for (int i = 0; i < 6; i++) {
    s += QString::asprintf("%02X", h->sMAC[i]);
    d += QString::asprintf("%02X", h->dMAC[i]);
    if (i != 5) {
      s += "-";
      d += "-";
    }
  }
  this->sMAC = s;
  this->dMAC = d;
  res += "Ethernet V2:\n";
  res += "  目的MAC:\t" + d + "\n ";
  res += "  源MAC:\t" + s + "\n";
  res += QString::asprintf("  上层协议:\t0x%04X\n", ntohs(h->protocol));

  switch (ntohs(h->protocol)) {
  case 0x0800: // IPv4
    return res + analyze_IPv4(next_header, next_size);
  case 0x86DD: // IPv6
    return res + analyze_IPv6(next_header, next_size);
  case 0x0806: // ARP
    return res + analyze_ARP(next_header, next_size);
  }
  return res;
}
QString Result::analyze_IPv4(void *data, int size) {
  QString res("");
  IPVersion = 4;
  void *next_header = (u_int8_t *)data + sizeof(IPv4);
  int next_size = size - sizeof(IPv4);
  IPv4 *h = (IPv4 *)data;
  res += QString::asprintf("\nIPv4:\n  头长度:\t%u\n", h->headerLength);
  res += QString::asprintf("  IP服务类型:\t0x%02X\n", h->tos);
  res += QString::asprintf("  总长度:\t%u\n", ntohs(h->length));
  res += QString::asprintf("  标志:\t0x%04X\n", ntohs(h->id));

  bool DF = ntohs(h->off) & 0x4000;
  bool MF = ntohs(h->off) & 0x2000;
  u_int16_t offset = ntohs(h->off) & 0x1FFF;

  res += QString::asprintf("  DF:\t%u\n", DF);
  res += QString::asprintf("  MF:\t%u\n", MF);
  res += QString::asprintf("  片偏移:\t%u\n", offset);

  res += QString::asprintf("  TTL:\t%u\n", h->ttl);
  res += QString::asprintf("  校验和:\t%u\n", ntohs(h->checksum));

  s = QString::asprintf("%u.%u.%u.%u", h->sIP.s_net, h->sIP.s_host, h->sIP.s_lh,
                        h->sIP.s_impno);
  d = QString::asprintf("%u.%u.%u.%u", h->dIP.s_net, h->dIP.s_host, h->dIP.s_lh,
                        h->dIP.s_impno);

  res += "  源IP:\t" + s + "\n  目的IP:\t" + d + "\n";
  res += QString::asprintf("  上层协议:\t%d\n", h->protocol);
  switch (h->protocol) {
  case 1: // ICMP
    return res + analyze_ICMP(next_header, next_size);
  case 2: // IGMP
    protocol = "IGMP";
    protocol_l2 = "IGMP";
    return res;
  case 6: // TCP
    return res + analyze_TCP(next_header, next_size);
  case 17: // UDP
    return res + analyze_UDP(next_header, next_size);
  case 88: // IGRP
  {
    protocol = "IGRP";
    protocol_l2 = "IGRP";
    return res;
  }
  case 89: // OSPF
    protocol = "OSPF";
    protocol_l2 = "OSPF";
    return res;
  }
  return res;
}

QString Result::analyze_IPv6(void *data, int size) {
  QString res;
  IPv6 *h = (IPv6 *)data;
  IPVersion = 6;
  void *next_header = (u_int8_t *)data + sizeof(IPv6);
  int next_size = size - sizeof(IPv6);

  u_int8_t trafficClass = ntohl(h->version_trafficClass_flowLabel) & 0x0FF00000;
  u_int32_t flowLabel = ntohl(h->version_trafficClass_flowLabel) & 0x000FFFFF;
  res += QString::asprintf("\nIPv6:\n  流量分类:\t0x%04X\n", trafficClass);
  res += QString::asprintf("  流标签:\t0x%05X\n", flowLabel);
  res += QString::asprintf("  有效负载:\t%u\n", ntohs(h->payloadLen));
  res += QString::asprintf("  跳数限制:\t%u\n", h->hopLimit);
  for (int i = 0; i < 8; i++) {
    s += QString::asprintf("%X", ntohs(h->sIP[i]));
    d += QString::asprintf("%X", ntohs(h->dIP[i]));
    if (i != 7) {
      s += ":";
      d += ":";
    }
  }
  res += "  源IP:\t" + s + "\n";
  res += "  目的IP:\t" + d + "\n";
  res += QString::asprintf("  上层协议:\t%d\n", h->nextHeader);

  switch (h->nextHeader) {
  case 6: // TCP
    return res + analyze_TCP(next_header, next_size);
  case 17: // UDP
    return res + analyze_UDP(next_header, next_size);
  case 58: // ICMPv6
  {
    protocol = "ICMPv6";
    protocol_l2 = "ICMPv6";
    return res;
  }
  case 59: // No Next Header
    return res;

    //扩展头分析未实现
  }
  return res;
}
QString Result::analyze_ARP(void *data, int size) {
  QString res(""), sip, tip, smac, tmac;
  protocol = "ARP";
  IPVersion = 1;
  ARP *h = (ARP *)data;

  res += QString::asprintf("\nARP:\n  硬件类型:\t0x%04X\n", ntohs(h->ar_hrd));
  res += QString::asprintf("  协议类型:\t0x%04X\n", ntohs(h->ar_pro));
  res += QString::asprintf("  MAC长度:\t%u\n", h->ar_hln);
  res += QString::asprintf("  IP长度:\t%u\n", h->ar_pln);
  res += QString::asprintf("  操作:\t%u\n", ntohs(h->ar_op));

  for (int i = 0; i < 6; i++) {
    smac += QString::asprintf("%02X", h->arp_sha[i]);
    tmac += QString::asprintf("%02X", h->arp_tha[i]);
    if (i != 5) {
      smac += "-";
      tmac += "-";
    }
  }
  s = sMAC;
  d = dMAC;
  sip = QString::asprintf("%u.%u.%u.%u", h->arp_spa[0], h->arp_spa[1],
                          h->arp_spa[2], h->arp_spa[3]);
  tip = QString::asprintf("%u.%u.%u.%u", h->arp_tpa[0], h->arp_tpa[1],
                          h->arp_tpa[2], h->arp_tpa[3]);
  res += "  发送者MAC:\t" + smac + "\n";
  res += "  发送者IP:\t" + sip + "\n";
  res += "  目标MAC:\t" + tmac + "\n";
  res += "  目标IP:\t" + tip + "\n";
  return res;
}
QString Result::analyze_ICMP(void *data, int size) {
  QString res("");
  protocol = "ICMP";
  protocol_l2 = "ICMP";
  ICMP *h = (ICMP *)data;
  res += "\nICMP:\n";
  res += QString::asprintf("  类型:\t%d\n", h->type);
  res += QString::asprintf("  代码:\t0x%d\n", h->code);
  res += QString::asprintf("  校验和:\t0x%04X\n", ntohs(h->checksum));
  return res;
}

QString Result::analyze_UDP(void *data, int size) {
  QString res("");
  void *next_header = (u_int8_t *)data + sizeof(UDP);
  int next_size = size - sizeof(UDP);
  Trans = 2;
  protocol = "UDP";
  UDP *h = (UDP *)data;
  sPort = ntohs(h->sPort);
  dPort = ntohs(h->dPort);
  res += QString::asprintf("\nUDP:\n  源端口:\t%u\n", sPort);
  res += QString::asprintf("  目的端口:\t%u\n", dPort);
  res += QString::asprintf("  长度:\t%u\n", ntohs(h->len));
  res += QString::asprintf("  校验和:\t%u\n", ntohs(h->checksum));
  if (sPort == 53 || dPort == 53) {
    protocol = "DNS";
    return res;
  }
  return res;
}
QString Result::analyze_TCP(void *data, int size) {
  QString res("");
  Trans = 1;
  protocol = "TCP";
  TCP *h = (TCP *)data;
  sPort = ntohs(h->sPort);
  dPort = ntohs(h->dPort);
  res += QString::asprintf("\nTCP:\n  源端口:\t%u\n", sPort);
  res += QString::asprintf("  目的端口:\t%u\n", dPort);
  res += QString::asprintf("  序号:\t%u\n", ntohl(h->seqNum));
  res += QString::asprintf("  确认号:\t%u\n", ntohl(h->ackNum));
  u_int16_t dataOffset =
      (ntohs(h->dataOffset_flags) >> 12) * 4; //原单位为4Byte,改为Byte
  bool URG = ntohs(h->dataOffset_flags) & 0x0020;
  bool ACK = ntohs(h->dataOffset_flags) & 0x0010;
  bool PSH = ntohs(h->dataOffset_flags) & 0x0008;
  bool RST = ntohs(h->dataOffset_flags) & 0x0004;
  bool SYN = ntohs(h->dataOffset_flags) & 0x0002;
  bool FIN = ntohs(h->dataOffset_flags) & 0x0001;
  res += QString::asprintf("  数据偏移:\t%u Byte\n", dataOffset);
  res += QString::asprintf("  URG:\t%u\n", URG);
  res += QString::asprintf("  ACK:\t%u\n", ACK);
  res += QString::asprintf("  PSH:\t%u\n", PSH);
  res += QString::asprintf("  RST:\t%u\n", RST);
  res += QString::asprintf("  SYN:\t%u\n", SYN);
  res += QString::asprintf("  FIN:\t%u\n", FIN);
  res += QString::asprintf("  滑动窗口:\t%u\n", ntohs(h->window));
  res += QString::asprintf("  紧急指针:\t%u\n", ntohs(h->urgent));

  void *next_header = (u_int8_t *)data + dataOffset;
  int next_size = size - dataOffset;

  if (sPort == 80 || dPort == 80) {
    return res + analyze_HTTP(next_header, next_size);
  }
  return res;
}

QString Result::analyze_HTTP(void *data, int size) {
  protocol = "HTTP";
  QString res = "\nHTTP:\n  HTTP报文:\n";
  res += QString::fromLocal8Bit((const char *)data, size);
  return res;
}
