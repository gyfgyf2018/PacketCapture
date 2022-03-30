#include "packetcapturer.h"
#include "packanalyzer.h"

// QVector<pcap_pkthdr *> headerList;
// QVector<u_char *> packetList;
extern QMutex l_packet;
extern QVector<Result *> resultList;

PacketCapturer::PacketCapturer(QObject *parent) : QObject{parent} {
  pcap_if_t *d;
  char pcap_src_if_string[] = PCAP_SRC_IF_STRING;
  if (pcap_findalldevs_ex(pcap_src_if_string, NULL, &alldevs, errbuf) != -1) {
    for (d = alldevs; d; d = d->next) {
      char dev[500] = "";
      if (d->description)
        strcat(dev, d->description);
      else
        strcat(dev, "Unknown");
      strcat(dev, " (");
      strcat(dev, d->name);
      strcat(dev, ")");
      char *temp = new char[500];
      strcpy(temp, dev);
      devList.append(temp);
    }
  }
}

void PacketCapturer::run() {
  running = true;
  //  puts("Packet Capture Start");
  emit CapturerStarted();
  pcap_if_t *d = alldevs;
  for (int i = 0; i < selectedDev; i++)
    d = d->next;

  if ((fp = pcap_open(d->name, 100 /*snaplen*/,
                      PCAP_OPENFLAG_PROMISCUOUS /*flags*/, 20 /*read timeout*/,
                      NULL /* remote authentication */, errbuf)) != NULL) {
    int res;
    struct pcap_pkthdr *header;
    const u_char *pkt_data;

    while (running) {
      res = pcap_next_ex(fp, &header, &pkt_data);
      if (res == 0)
        /* Timeout elapsed */
        continue;

      l_packet.lock();
      auto temp1 = new pcap_pkthdr;
      *temp1 = *header;
      //      headerList.append(temp1);

      auto temp2 = new u_char[header->caplen];
      for (int i = 0; i < header->caplen; i++) {
        temp2[i] = pkt_data[i];
      }
      //      packetList.append(temp2);
      resultList.append(new Result(temp1, temp2));
      l_packet.unlock();

      emit Captured();
      //      puts("Packet Captured!");
    }
  }
  //  puts("Capture Stopped!");
  emit CapturerStoped();
}
