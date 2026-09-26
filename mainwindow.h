#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QUdpSocket>
#include "ReliableUDPSocket.h"
#include <QSet>
QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
signals:
    void mesajPrimit(QString mesaj);
private slots:
    void on_sendButton_clicked();
    void afiseazaMesaj(QString mesaj);
    void on_attachButton_clicked();

private:
    Ui::MainWindow *ui;
    ReliableUDPSocket socket_chat;
    QUdpSocket *radarSocket;
    QSet<QString> peersDescoperiti;
    QString ipTinta = "";


    long long cheieSecreta = 0;
    long long calculModulo(long long baza, long long exponent, long long mod);

    void pornesteRetea();
    QByteArray aplicaXor(QByteArray date);
};
#endif // MAINWINDOW_H
