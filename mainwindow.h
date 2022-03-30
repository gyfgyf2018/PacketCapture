#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include "packanalyzer.h"
#include "packetcapturer.h"
#include <QMainWindow>
#include <QStandardItemModel>

QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

class MainWindow : public QMainWindow {
  Q_OBJECT

public:
  MainWindow(QWidget *parent = nullptr);
  ~MainWindow();

private slots:
  void devSelected(int);
  void packSelected(QModelIndex index);
  void stopCapturing();
  void captureStarted();
  void captureStopped();
  void showPack(Result *);
  void filter();
  void clearPack();

private:
  Ui::MainWindow *ui;
  PacketCapturer *pc;
  PackAnalyzer *pa;
  QThread *pcT, *paT;
  QStandardItemModel *model;
  int cntResults = 0;
  bool filterJudge(Result *);
  bool portJudge(Result *);
  bool IPJudge(Result *);
  bool protocolJudge(Result *);
};
#endif // MAINWINDOW_H
