#include "mainwindow.h"
#undef close // Anulăm macro-ul de Windows ca să protejăm funcțiile fisier.close()
#include "ui_mainwindow.h"
#include <QCoreApplication>
#include <chrono>
#include <QInputDialog>
#include <thread>
#include <QString>
#include <QFileDialog>
#include <QTimer>
#include <QNetworkDatagram>
#include <QUdpSocket>
#include <time.h>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    connect(this, &MainWindow::mesajPrimit, this, &MainWindow::afiseazaMesaj, Qt::QueuedConnection);
    connect(ui->messageInput, &QLineEdit::returnPressed, this, &MainWindow::on_sendButton_clicked);

    // 1. INIȚIALIZĂM RADARUL PE PORTUL 8081
    radarSocket = new QUdpSocket(this);
    radarSocket->bind(8081, QUdpSocket::ShareAddress);

    // 2. ASCULTĂM PE RADAR (Suntem mereu cu urechile ciulite)
    connect(radarSocket, &QUdpSocket::readyRead, this, [this]() {
        while (radarSocket->hasPendingDatagrams()) {
            QNetworkDatagram datagram = radarSocket->receiveDatagram();
            QByteArray data = datagram.data();

            if (data.startsWith("DISCOVER:")) {
                QString ipExpeditor = datagram.senderAddress().toString();
                ipExpeditor.remove("::ffff:");
                // Ignorăm ecoul propriului nostru IP
                if (!datagram.senderAddress().isLoopback() && !peersDescoperiti.contains(ipExpeditor)) {
                    peersDescoperiti.insert(ipExpeditor);
                    emit mesajPrimit("[Auto-Discovery] S-a găsit un Peer la adresa: " + ipExpeditor);

                    if (ipTinta.isEmpty()){
                        ipTinta = ipExpeditor;
                    }
                }
            }
        }
    });

    // 3. PORNIM PULSUL RADARULUI
    QTimer* discoveryTimer = new QTimer(this);
    connect(discoveryTimer, &QTimer::timeout, this, [this](){
        QByteArray mesaj = "DISCOVER:MARIUS";
        // Trimitem strigătul către toată rețeaua pe 8081
        radarSocket->writeDatagram(mesaj, QHostAddress::Broadcast, 8081);
    });
    //discoveryTimer->start(2000);
    discoveryTimer->start(500);

    // 4. PORNIM MOTORUL C++
    std::thread fir_retea(&MainWindow::pornesteRetea, this);
    fir_retea.detach();
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::pornesteRetea() {

    // NOD UNIFICAT: Încercăm automat să fim Gazda
    if (socket_chat.listen(8080)) {
        emit mesajPrimit("[Sistem] Suntem Gazdă. Așteptăm conexiuni...");
    }
    else {
        emit mesajPrimit("[Sistem] Suntem Client. Așteptăm un semnal de la Radar...");

        // Oprim motorul C++ din execuție până când radarul găsește un IP
        int incercari = 0;
        while (ipTinta.isEmpty() && incercari < 3) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500)); // Verificăm de 2 ori pe secundă
            incercari++;
        }

        if (ipTinta.isEmpty()){
            emit mesajPrimit("[Sistem] Test local detectat de Windows. Folosim 127.0.0.1 ...");
            ipTinta = "127.0.0.1";
        }
        else
            emit mesajPrimit("[Sistem] Inițiem Handshake-ul cu IP: " + ipTinta + " ...");

        // Ne conectăm la IP-ul real găsit de radar, nu la 127.0.0.1!
        socket_chat.connect(ipTinta.toStdString(), 8080);

        emit mesajPrimit("[Sistem] Conexiune stabilită cu succes!");
    }

    emit mesajPrimit("[Securitate] Generăm cheile Diffie-Hellman...");

    long long P = 2147483647;
    long long G = 16807;

    srand(time(NULL) + (long long)this);

    long long secretPersonal =  rand() %1000 + 1;

    long long publicKeyNostru = calculModulo(G, secretPersonal, P);

    std::string msgKey = "KEY:" + std::to_string(publicKeyNostru);
    socket_chat.send_data(msgKey.c_str(), msgKey.length());

    char buffer[4096];
    long long publicKeyPrimit = 0;

    while(true){
        int bytes = socket_chat.recv_data(buffer, sizeof(buffer));
        if(bytes>0){
            QByteArray pachet(buffer, bytes);
            if( pachet.startsWith("KEY:")){
                publicKeyPrimit = pachet.mid(4).toLongLong();
                break;
            }
        }
    }

    cheieSecreta = calculModulo(publicKeyPrimit, secretPersonal, P);
    emit mesajPrimit("[Securitate] Cheie E2EE stabilită cu succes: " + QString::number(cheieSecreta));

    QFile fisierPrimit;

    // Bucla infinită de ascultare a motorului de chat/fișiere
    while (true) {
        int bytes = socket_chat.recv_data(buffer, sizeof(buffer));

        if (bytes > 0) {
            QByteArray pachet(buffer, bytes);

            if (pachet.startsWith("TXT:")) {
                QByteArray textCriptat = pachet.mid(4);
                QByteArray textDecriptat = aplicaXor(textCriptat);
                emit mesajPrimit(QString::fromUtf8(textDecriptat));
            }
            else if (pachet.startsWith("FILE:")) {
                QString numeFisier = QString::fromUtf8(pachet.mid(5));
                emit mesajPrimit("[Sistem] Primim fișierul: " + numeFisier);

                // Creăm fișierul local
                fisierPrimit.setFileName("primit_" + numeFisier);
                fisierPrimit.open(QIODevice::WriteOnly);
            }
            else if (pachet.startsWith("BIN:")) {
                if (fisierPrimit.isOpen()) {
                    QByteArray dateCriptate = pachet.mid(4);
                    QByteArray dateDecriptate = aplicaXor(dateCriptate);
                    fisierPrimit.write(dateDecriptate);
                    fisierPrimit.flush();
                }
            }
            else if (pachet == "END_FILE") {
                if (fisierPrimit.isOpen()) {
                    fisierPrimit.close();
                    emit mesajPrimit("[Sistem] Fișier salvat cu succes pe disk!");
                }
            }
            else {
                emit mesajPrimit(QString::fromUtf8(pachet)); // Fallback pentru mesaje simple
            }
        }
    }
}

void MainWindow::afiseazaMesaj(QString mesaj){
    ui->chatHistory->addItem(mesaj);
    ui->chatHistory->scrollToBottom();
}

void MainWindow::on_sendButton_clicked(){
    QString text = ui->messageInput->text();
    if (text.isEmpty()) return;

    ui->chatHistory->addItem("Tu: " + text);
    ui->chatHistory->scrollToBottom();

    // std::string text_std = "TXT:"+text.toStdString();
    // socket_chat.send_data(text_std.c_str(),text_std.length());

    QByteArray textCriptat = aplicaXor(text.toUtf8());
    QByteArray pachetFinal = "TXT:";
    pachetFinal.append(textCriptat);
    socket_chat.send_data(pachetFinal.constData(),pachetFinal.size());
    ui->messageInput->clear();
}
void MainWindow::on_attachButton_clicked()
{
    QString filePath = QFileDialog::getOpenFileName(this, "Alege un fisier pentru transfer", "", "Toate Fisierele (*.*)");
    if (filePath.isEmpty()) return;

    QFileInfo fileInfo(filePath);
    QString fileName = fileInfo.fileName();
    ui->chatHistory->addItem("[Sistem] Pregatit pentru transfer: " + fileName);
    ui->chatHistory->scrollToBottom();

    // Blocăm butonul ca să nu dăm click de două ori
    ui->attachButton->setEnabled(false);

    // Transformăm datele în C++ standard ca să le putem trimite în siguranță către noul thread
    std::string fileNameStd = fileName.toStdString();
    std::string filePathStd = filePath.toStdString();

    // PORNIM TRANSFERUL ÎN FUNDAL (MULTITHREADING)
    std::thread([this, filePathStd, fileNameStd]() {

        // 1. Trimitem antetul
        std::string header = "FILE:" + fileNameStd;
        socket_chat.send_data(header.c_str(), header.length());

        // 2. Citim și trimitem fișierul
        QFile fisier(QString::fromStdString(filePathStd));
        if (fisier.open(QIODevice::ReadOnly)) {
            while(!fisier.atEnd()){
                QByteArray chunk = fisier.read(256);
                if(chunk.isEmpty()) break; // Siguranță împotriva blocajelor

                QByteArray chunkCriptat = aplicaXor(chunk);
                QByteArray pachet;
                pachet.append("BIN:");
                pachet.append(chunkCriptat);
                socket_chat.send_data(pachet.constData(), pachet.size());

                // Acum că suntem în fundal, putem folosi o pauză rapidă de 2ms
                std::this_thread::sleep_for(std::chrono::milliseconds(2));
            }
            fisier.close();

            // 3. Semnalul de final
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            std::string finalMsg = "END_FILE";
            socket_chat.send_data(finalMsg.c_str(), finalMsg.length());
        }

        // 4. ACTUALIZĂM INTERFAȚA GRAFICĂ (Revenim pe firul principal în siguranță)
        QMetaObject::invokeMethod(this, [this]() {
            ui->chatHistory->addItem("[Sistem] Fișier trimis complet prin rețea!");
            ui->chatHistory->scrollToBottom();
            ui->attachButton->setEnabled(true);
        });

    }).detach(); // Deconectăm firul pentru a rula independent
}

long long MainWindow::calculModulo(long long baza, long long exponent, long long mod){
    long long rezultat = 1;
    baza = baza % mod;
    while(exponent > 0){
        if(exponent % 2 == 1){
            rezultat = (rezultat * baza) % mod;
        }
        exponent = exponent >> 1;
        baza = (baza * baza ) % mod;
    }
    return rezultat;
}

QByteArray MainWindow::aplicaXor(QByteArray date){
    QByteArray rezultat = date;
    char* cheie = (char*)&cheieSecreta;

    for(int i = 0; i < rezultat.size(); i++){
        rezultat[i] = rezultat[i] ^ cheie[i%sizeof(long long)];
    }
    return rezultat;
}
