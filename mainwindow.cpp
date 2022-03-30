#include "mainwindow.h"
#include "./ui_mainwindow.h"

extern QVector<Result *> resultList;
QVector<Result *> showList;

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent), ui(new Ui::MainWindow), pc(new PacketCapturer),
      pa(new PackAnalyzer), model(new QStandardItemModel) {
  ui->setupUi(this);
  for (int i = 0; i < pc->devList.size(); i++) {
    ui->adapterList->addItem(pc->devList[i]);
  }

  model->setColumnCount(5);
  model->setHeaderData(0, Qt::Horizontal, QString("时间戳"));
  model->setHeaderData(1, Qt::Horizontal, QString("源"));
  model->setHeaderData(2, Qt::Horizontal, QString("目的"));
  model->setHeaderData(3, Qt::Horizontal, QString("协议"));
  model->setHeaderData(4, Qt::Horizontal, QString("抓取长度/总长度"));
  //  model->setHeaderData(5, Qt::Horizontal, QString("源MAC"));
  //  model->setHeaderData(6, Qt::Horizontal, QString("目的MAC"));
  ui->packTable->setModel(model);
  ui->packTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
  ui->packTable->horizontalHeader()->setDefaultAlignment(Qt::AlignHCenter);

  // Pack Capture Thread
  pcT = new QThread;
  pc->moveToThread(pcT);
  connect(ui->startButton, &QPushButton::clicked, pc, &PacketCapturer::run);
  connect(ui->stopButton, &QPushButton::clicked, this,
          &MainWindow::stopCapturing);
  connect(pc, &PacketCapturer::CapturerStarted, this,
          &MainWindow::captureStarted);
  connect(pc, &PacketCapturer::CapturerStoped, this,
          &MainWindow::captureStopped);
  pcT->start();

  // Pack Analyze Thread
  paT = new QThread;
  pa->moveToThread(paT);
  connect(ui->startButton, &QPushButton::clicked, pa, &PackAnalyzer::run);
  connect(pa, &PackAnalyzer::analyzed, this, &MainWindow::showPack);
  paT->start();
}

MainWindow::~MainWindow() { delete ui; }

void MainWindow::devSelected(int index) {
  pc->selectedDev = index;
  printf("%s:%d\n", "dev selected", index);
}

void MainWindow::stopCapturing() { pc->running = false; }

void MainWindow::captureStarted() {
  ui->startButton->setDisabled(true);
  ui->stopButton->setEnabled(true);
  ui->clearButton->setDisabled(true);
}
void MainWindow::captureStopped() {
  ui->startButton->setEnabled(true);
  ui->stopButton->setDisabled(true);
  ui->clearButton->setEnabled(true);
  pa->running = false;
}
void MainWindow::showPack(Result *res) {
  model->setItem(
      cntResults, 0,
      new QStandardItem(QString::asprintf("%d.%03d", res->header->ts.tv_sec,
                                          res->header->ts.tv_usec)));
  model->setItem(cntResults, 1, new QStandardItem(res->s));
  model->setItem(cntResults, 2, new QStandardItem(res->d));
  model->setItem(cntResults, 3, new QStandardItem(res->protocol));
  model->setItem(cntResults, 4,
                 new QStandardItem(QString::asprintf(
                     "%d/%d", res->header->caplen, res->header->len)));

  //  model->setItem(num, 5, new QStandardItem(res->sMAC));
  //  model->setItem(num, 6, new QStandardItem(res->dMAC));
  cntResults++;
  ui->packTable->viewport()->update();
  showList.append(res);
}

void MainWindow::packSelected(QModelIndex index) {
  int ind = index.row();

  QString str = showList[ind]->info + "\n";
  str += "\nRawData:\n";
  for (int i = 0; i < showList[ind]->header->caplen; i++) {
    str += QString::asprintf("%02X ", showList[ind]->data[i]);
  }
  ui->packInfo->setPlainText(str);
  ui->packInfo->update();
}
bool MainWindow::portJudge(Result *res) {
  if (ui->sPortCheck->isChecked() && ui->dPortCheck->isChecked()) {
    if (ui->orPortCheck->isChecked())
      return res->sPort == ui->sPortFilter->value() ||
             res->dPort == ui->dPortFilter->value();
    else
      return res->sPort == ui->sPortFilter->value() &&
             res->dPort == ui->dPortFilter->value();
  } else if (ui->sPortCheck->isChecked())
    return res->sPort == ui->sPortFilter->value();
  else if (ui->dPortCheck->isChecked())
    return res->dPort == ui->dPortFilter->value();
  else
    return true;
}

bool MainWindow::IPJudge(Result *res) {
  if (ui->sIPCheck->isChecked() && ui->dIPCheck->isChecked()) {
    if (ui->orIPCheck->isChecked())
      return res->s == ui->sIPFilter->text() || res->d == ui->dIPFilter->text();
    else
      return res->s == ui->sIPFilter->text() && res->d == ui->dIPFilter->text();
  } else if (ui->sIPCheck->isChecked())
    return res->s == ui->sIPFilter->text();
  else if (ui->dIPCheck->isChecked())
    return res->d == ui->dIPFilter->text();
  else
    return true;
}

bool MainWindow::protocolJudge(Result *res) {
  bool ipv4 = false, ipv6 = false, arp = false, icmp = false, elsel2 = false,
       tcp = false, udp = false;
  if (ui->IPv4Check->isChecked() && res->IPVersion == 4)
    ipv4 = true;
  if (ui->IPv6Check->isChecked() && res->IPVersion == 6)
    ipv6 = true;
  if (ui->ARPCheck->isChecked() && res->IPVersion == 1)
    arp = true;

  if (ui->ICMPCheck->isChecked() && res->protocol_l2 == "ICMP")
    icmp = true;
  if (ui->elseCheckL2->isChecked() && res->protocol_l2 != "" &&
      res->protocol_l2 != "ICMP")
    elsel2 = true;

  if (ui->TCPCheck->isChecked() && res->Trans == 1)
    tcp = true;
  if (ui->UDPCheck->isChecked() && res->Trans == 2)
    udp = true;
  return (ipv4 || ipv6 || arp) && (arp || icmp || elsel2 || tcp || udp);
}
bool MainWindow::filterJudge(Result *res) {
  return portJudge(res) && IPJudge(res) && protocolJudge(res);
}
void MainWindow::filter() {
  ui->packTable->model()->removeRows(0, model->rowCount());
  cntResults = 0;
  showList.clear();

  for (Result *res : resultList)
    if (filterJudge(res))
      showPack(res);
}
void MainWindow::clearPack() {
  for (Result *res : resultList) {
    delete res->header;
    delete[] res->data;
    delete res;
  }
  resultList.clear();
  ui->packTable->model()->removeRows(0, model->rowCount());
  cntResults = 0;
}
