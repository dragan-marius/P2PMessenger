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

    //Auto-Discovery UDP Radar
    //We bind a secondary UDP socket on port 8081 specifically for broadcasting 'DISCOVER:' datagrams
    //This allows nodes to automatically find each other on the local network without hardcoding IPs
    radarSocket = new QUdpSocket(this);
    radarSocket->bind(8081, QUdpSocket::ShareAddress);

    connect(radarSocket, &QUdpSocket::readyRead, this, [this]() {
        while (radarSocket->hasPendingDatagrams()) {
            QNetworkDatagram datagram = radarSocket->receiveDatagram();
            QByteArray data = datagram.data();

            if (data.startsWith("DISCOVER:")) {
                QString ipExpeditor = datagram.senderAddress().toString();
                ipExpeditor.remove("::ffff:");
                // Ignore our own IP.
                if (!datagram.senderAddress().isLoopback() && !peersDescoperiti.contains(ipExpeditor)) {
                    peersDescoperiti.insert(ipExpeditor);
                    emit mesajPrimit("[Auto-Discovery] A peer was found at the address: " + ipExpeditor);

                    if (ipTinta.isEmpty()){
                        ipTinta = ipExpeditor;
                    }
                }
            }
        }
    });

    QTimer* discoveryTimer = new QTimer(this);
    connect(discoveryTimer, &QTimer::timeout, this, [this](){
        QByteArray mesaj = "DISCOVER:MARIUS";
        // We are sending the broadcast to the entire network on port 8081.
        radarSocket->writeDatagram(mesaj, QHostAddress::Broadcast, 8081);
    });
    discoveryTimer->start(500);
    std::thread fir_retea(&MainWindow::pornesteRetea, this);
    fir_retea.detach();
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::pornesteRetea() {

    // Symmetric Node Unification
    //The application avoids strict Server/Client roles. It attempts to bind on 8080 as a Host
    //If the port is already in use, it cleanly falls back
    //to Client mode and waits for radar signals to connect
    if (socket_chat.listen(8080)) {
        emit mesajPrimit("[System] We are the host. Awaiting connections....");
    }
    else {
        emit mesajPrimit("[System] We are the Client. We are awaiting a signal from the Radar...");

        int incercari = 0;
        while (ipTinta.isEmpty() && incercari < 3) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            incercari++;
        }

        if (ipTinta.isEmpty()){
            emit mesajPrimit("[System] Local test detected by Windows. Using 127.0.0.1. ...");
            ipTinta = "127.0.0.1";
        }
        else
            emit mesajPrimit("[System] Initiating handshake with IP: " + ipTinta + " ...");

        socket_chat.connect(ipTinta.toStdString(), 8080);

        emit mesajPrimit("[System] Connection successfully established!");
    }

    //[SECURITY] Diffie-Hellman Key Exchange
    //We negotiate a shared symmetric key over the unecrypted channel using prime P and base G
    emit mesajPrimit("[Security] Generating Diffie-Hellman keys...");

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
    emit mesajPrimit("[Security] E2EE key successfully established: " + QString::number(cheieSecreta));

    QFile fisierPrimit;

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
                emit mesajPrimit("[System] Receiving the file: " + numeFisier);

                fisierPrimit.setFileName("receive_" + numeFisier);
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
                    emit mesajPrimit("[System] File successfully saved to disk!");
                }
            }
            else {
                emit mesajPrimit(QString::fromUtf8(pachet));
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

    ui->chatHistory->addItem("You: " + text);
    ui->chatHistory->scrollToBottom();

    QByteArray textCriptat = aplicaXor(text.toUtf8());
    QByteArray pachetFinal = "TXT:";
    pachetFinal.append(textCriptat);
    socket_chat.send_data(pachetFinal.constData(),pachetFinal.size());
    ui->messageInput->clear();
}
void MainWindow::on_attachButton_clicked()
{
    //[CONCURENCY] Detached Background File Transfer
    //Reading and encrypting files chunk-by-chunk is CPU intensive and blocks the event loop
    //We offload the transmission logic to an isolated background std::thread to keep the Qt UI fluid
    QString filePath = QFileDialog::getOpenFileName(this, "Select a file for transfer", "", "All Files(*.*)");
    if (filePath.isEmpty()) return;

    QFileInfo fileInfo(filePath);
    QString fileName = fileInfo.fileName();
    ui->chatHistory->addItem("[System] Ready for transfer: " + fileName);
    ui->chatHistory->scrollToBottom();

    ui->attachButton->setEnabled(false);

    std::string fileNameStd = fileName.toStdString();
    std::string filePathStd = filePath.toStdString();

    std::thread([this, filePathStd, fileNameStd]() {

        // 1. Send the header.
        std::string header = "FILE:" + fileNameStd;
        socket_chat.send_data(header.c_str(), header.length());

        // 2. Read and send the file.
        QFile fisier(QString::fromStdString(filePathStd));
        if (fisier.open(QIODevice::ReadOnly)) {
            while(!fisier.atEnd()){
                QByteArray chunk = fisier.read(256);
                if(chunk.isEmpty()) break;

                QByteArray chunkCriptat = aplicaXor(chunk);
                QByteArray pachet;
                pachet.append("BIN:");
                pachet.append(chunkCriptat);
                socket_chat.send_data(pachet.constData(), pachet.size());

                std::this_thread::sleep_for(std::chrono::milliseconds(2));
            }
            fisier.close();

            // 3. Final signal
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            std::string finalMsg = "END_FILE";
            socket_chat.send_data(finalMsg.c_str(), finalMsg.length());
        }

        // 4. UPDATING THE GRAPHICAL INTERFACE
        //[THREAD SAFETY] Cross-Thread UI Updates
        //Qt Widgets are not thread-safe. We must use QMetaObject::invokeMethod to safely queue
        //the UI update back onto the main event loop
        QMetaObject::invokeMethod(this, [this]() {
            ui->chatHistory->addItem("[System] File transfer via network complete!");
            ui->chatHistory->scrollToBottom();
            ui->attachButton->setEnabled(true);
        });

    }).detach();
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
