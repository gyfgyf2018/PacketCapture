#ifndef PACKANALYZER_H
#define PACKANALYZER_H

#include <QMutex>
#include <QObject>
#include <QThread>
#include <pcap.h>

class header {
public:
  virtual QString analyze(void *, int size) = 0;
};

/* MAC 包 */
struct MAC {
  u_int8_t dMAC[6];   //目的Mac
  u_int8_t sMAC[6];   //源Mac
  u_int16_t protocol; //上层协议
};

/* IPv4 包 */
struct IPv4 {
  u_int8_t headerLength : 4; //头长度
  u_int8_t version : 4;
  u_int8_t tos;     //服务类型
  u_int16_t length; //总长度
  u_int16_t id;     //标识符
  u_int16_t off;    //片偏移
  u_int8_t ttl;
  u_int8_t protocol;  //上层协议
  u_int16_t checksum; //检验和
  struct in_addr sIP;
  struct in_addr dIP;
};

/* IPv6 包 */
struct IPv6 {
  u_int32_t version_trafficClass_flowLabel; //版本号+通信类别+流标记
  u_int16_t payloadLen;                     //有效长度
  u_int8_t nextHeader;                      //下一头部（上层协议）
  u_int8_t hopLimit;                        //跳数限制
  u_int16_t sIP[8];
  u_int16_t dIP[8];
};

/* ICMP 包 */
struct ICMP {
  u_int8_t type;      //类型
  u_int8_t code;      //代码
  u_int16_t checksum; //校验和
  //其余字节未识别
};

/* ARP 包 */
struct ARP {
  u_int16_t ar_hrd;    //硬件类型
  u_int16_t ar_pro;    //协议类型
  u_int8_t ar_hln;     // MAC长度
  u_int8_t ar_pln;     // IP长度
  u_int16_t ar_op;     //操作类型
  u_int8_t arp_sha[6]; //发送者MAC
  u_int8_t arp_spa[4]; //发送者IP （不使用in_addr结构体 以保证内存连续分配）
  u_int8_t arp_tha[6]; //目标MAC
  u_int8_t arp_tpa[4]; //目标IP
};

/* UDP 包 */
struct UDP {
  u_int16_t sPort;    //源端口
  u_int16_t dPort;    //目的端口
  u_int16_t len;      //总长度
  u_int16_t checksum; //校验和
};

/* TCP 包 */
struct TCP {
  u_int16_t sPort;            //源端口
  u_int16_t dPort;            //目的端口
  u_int32_t seqNum;           //序列号
  u_int32_t ackNum;           //应答号
  u_int16_t dataOffset_flags; //数据偏移量（包头长度）+标识位
  u_int16_t window;           //滑动窗口
  u_int16_t checksum;         //校验和
  u_int16_t urgent;           //紧急指针
};

/* DNS 包 */
// struct DNS {
//   u_int16_t sign;        //唯一标识
//   u_int8_t symbol[2];    //标志
//   u_int8_t QR;           //查询还是响应报文
//   u_int16_t questionNum; //问题数目
//   u_int16_t answerNum;   //回答数目
//   u_int16_t au_answer;   //权威回答数目
//   u_int16_t ex_answer;   //附加回答数目
// };

/* HTTP 包 */
struct HTTP {
  QString HttpData; //打印信息
};

class Result {
public:
  Result(pcap_pkthdr *, u_char *);
  void getInfo();
  pcap_pkthdr *header;
  u_char *data;
  QString info;
  QString sMAC, dMAC, s, d, protocol, protocol_l2;
  int sPort, dPort;
  int IPVersion = 0, Trans = 0;

private:
  QString analyze_MAC(void *, int size);
  QString analyze_IPv4(void *, int size);
  QString analyze_IPv6(void *, int size);
  QString analyze_ARP(void *, int size);
  QString analyze_ICMP(void *, int size);
  QString analyze_TCP(void *, int size);
  QString analyze_UDP(void *, int size);
  QString analyze_DNS(void *, int size);
  QString analyze_HTTP(void *, int size);
};

class PackAnalyzer : public QObject {
  Q_OBJECT
public:
  explicit PackAnalyzer(QObject *parent = nullptr);
  void run();
  bool running = false;

signals:
  int analyzed(Result *);
};

#endif // PACKANALYZER_H
