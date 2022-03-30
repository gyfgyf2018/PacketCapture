#ifndef PACKETCAPTURER_H
#define PACKETCAPTURER_H


#include <QObject>
#include <QThread>
#include <pcap.h>



class PacketCapturer : public QObject {
  Q_OBJECT
public:
  explicit PacketCapturer(QObject *parent = nullptr);

  void run();
  QVector<char *> devList;
  int selectedDev = -1;
  bool running;

signals:
  void CapturerStarted();
  void CapturerStoped();
  void Captured();

private:
  pcap_if_t *alldevs;
  pcap_t *fp;
  char errbuf[PCAP_ERRBUF_SIZE];

public slots:
};

#endif // PACKETCAPTURER_H
