#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QUdpSocket>
#include "ReliableUDPSocket.h"
#include <QSet>
#include <vector>
#include <cstdint>
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
    QByteArray encryptedFileBuffer;


    long long dh_secret = 0;
    long long calculModulo(long long baza, long long exponent, long long mod);

    void pornesteRetea();
    std::vector<uint8_t> deriveAESKey(long long dh_secret);
    std::vector<uint8_t> encryptAES_GCM(const std::vector<uint8_t> &plaintext, const std::vector<uint8_t> &key);
    std::vector<uint8_t> decryptAES_GCM(const std::vector<uint8_t>& packet, const std::vector<uint8_t>& key);
};
#endif // MAINWINDOW_H
