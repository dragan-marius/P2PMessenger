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
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <vector>
#include <stdexcept>

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

std::vector<uint8_t> MainWindow::MainWindow::deriveAESKey(long long dh_secret){
    std::vector<uint8_t> key(SHA256_DIGEST_LENGTH);
    SHA256(reinterpret_cast<const unsigned char*>(&dh_secret), sizeof(dh_secret), key.data());
    return key;
}

std::vector<uint8_t> MainWindow::encryptAES_GCM(const std::vector<uint8_t> &plaintext, const std::vector<uint8_t> &key){
    //Generate a random 12-byte IV (so that identical messages appear different on the wire)
    std::vector<uint8_t> iv(12);
    RAND_bytes(iv.data(), 12);

    //Providing OpenSSL for AES2-256-GCM
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key.data(), iv.data());

    //Encrypt the text
    std::vector<uint8_t> ciphertext(plaintext.size());
    int len;
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size());
    int cipher_text_len = len;

    EVP_EncryptFinal_ex(ctx, ciphertext.data() +  len, &len);

    //Extract the 16-byte security seal (tag).
    std::vector<uint8_t> tag(16);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data());
    EVP_CIPHER_CTX_free(ctx);

    //Bundle everything into a single package.
    std::vector<uint8_t> secure_packet;
    secure_packet.insert(secure_packet.end(), iv.begin(), iv.end());
    secure_packet.insert(secure_packet.end(), ciphertext.begin(), ciphertext.end());
    secure_packet.insert(secure_packet.end(), tag.begin(), tag.end());
    return secure_packet;
}
std::vector<uint8_t> MainWindow::decryptAES_GCM(const std::vector<uint8_t>& packet, const std::vector<uint8_t>& key){
    if (packet.size() < 28){
        //valid packet
        //12 bytes(IV) + 16 bytes (tag)
        throw std::runtime_error("Invalid or corrupted packet.");
    }
    std::vector<uint8_t> iv(packet.begin(), packet.begin() + 12);
    std::vector<uint8_t> ciphertext(packet.begin() + 12, packet.end() - 16);
    std::vector<uint8_t> tag(packet.end() - 16, packet.end());

    //Providing OpenSSL for decrypt
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key.data(), iv.data());

    //Decrypt the text
    std::vector<uint8_t> plaintext(ciphertext.size());
    int len;
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size());
    int plaintext_len = len;

    //Verify tag
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag.data());

    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0){
        plaintext_len+= len;
        plaintext.resize(plaintext_len);
        return plaintext;
    } else {
        throw std::runtime_error("E2EE security error: Tampered packet or incorrect key!");
    }

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

    dh_secret = calculModulo(publicKeyPrimit, secretPersonal, P);
    emit mesajPrimit("[Security] E2EE key successfully established: " + QString::number(dh_secret));

    QFile fisierPrimit;

    while (true) {
        int bytes = socket_chat.recv_data(buffer, sizeof(buffer));

        if (bytes > 0) {
            QByteArray pachet(buffer, bytes);

            if (pachet.startsWith("TXT:")) {
                QByteArray rawPacket = pachet.mid(4);
                std::vector<uint8_t> securePacket(rawPacket.begin(), rawPacket.end());
                std::vector<uint8_t> aesKey = deriveAESKey(dh_secret);
                try {
                    std::vector<uint8_t> decryptedData = decryptAES_GCM(securePacket, aesKey);
                    QString decryptedText = QString::fromUtf8(reinterpret_cast<const char*>(decryptedData.data()), decryptedData.size());
                    emit mesajPrimit("Peer: " + decryptedText);
                } catch (const std::exception& e) {
                    emit mesajPrimit(QString("[Security] Packet rejected: %1").arg(e.what()));
                }
            }
            else if (pachet.startsWith("FILE:")) {
                QString numeFisier = QString::fromUtf8(pachet.mid(5));
                emit mesajPrimit("[System] Receiving the file: " + numeFisier);

                fisierPrimit.setFileName("receive_" + numeFisier);
                fisierPrimit.open(QIODevice::WriteOnly);
            }
            else if (pachet.startsWith("BIN:")) {
                if (fisierPrimit.isOpen()) {
                    //Accumulate encrypted data chunks into the buffer
                    QByteArray incomingEncryptedData = pachet.mid(4);
                    encryptedFileBuffer.append(incomingEncryptedData);
                }
            }
            else if (pachet == "END_FILE") {
                if (fisierPrimit.isOpen()) {
                    std::vector<uint8_t> encryptedDataVec(encryptedFileBuffer.begin(), encryptedFileBuffer.end());
                    std::vector<uint8_t> aesKey = deriveAESKey(dh_secret);
                    try{
                        std::vector<uint8_t> decryptedDataVec = decryptAES_GCM(encryptedDataVec, aesKey);
                        QByteArray decryptedData(reinterpret_cast<const char*>(decryptedDataVec.data()), decryptedDataVec.size());

                        fisierPrimit.write(decryptedData);
                        fisierPrimit.close();
                        emit mesajPrimit("[System] File successfully saved to disk!");
                    } catch (const std::exception& e){
                        fisierPrimit.close();
                        emit mesajPrimit(QString("[Error] File decryption failed: %1!").arg(e.what()));
                    }
                    encryptedFileBuffer.clear();


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

    QByteArray utfText = text.toUtf8();
    std::vector<uint8_t> plaintext(utfText.begin(), utfText.end());
    std::vector<uint8_t> aesKey = deriveAESKey(dh_secret);
    std::vector<uint8_t> encryptedData = encryptAES_GCM(plaintext, aesKey);
    QByteArray textCriptat(reinterpret_cast<const char*> (encryptedData.data()), encryptedData.size());
    QByteArray pachetFinal = "TXT:";
    pachetFinal.append(textCriptat);
    socket_chat.send_data(pachetFinal.constData(),pachetFinal.size());
    ui->messageInput->clear();
}

void MainWindow::on_attachButton_clicked()
{
    //[CONCURRENCY] Detached Background File Transfer
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
        QFile file(QString::fromStdString(filePathStd));
        if (file.open(QIODevice::ReadOnly)) {
            QByteArray fileContent = file.readAll();
            file.close();

            std::vector<uint8_t> unencryptedData(fileContent.begin(), fileContent.end());
            std::vector<uint8_t> aesKey = deriveAESKey(dh_secret);
            std::vector<uint8_t> encryptedData = encryptAES_GCM(unencryptedData, aesKey);

            int currentOffset =  0;
            int chunkSize = 1024;

            while (currentOffset < encryptedData.size()){
                int bytesToSend = std::min(chunkSize, static_cast<int>(encryptedData.size() - currentOffset));
                QByteArray encryptedChunk(reinterpret_cast<const char*>(encryptedData.data() + currentOffset), bytesToSend);

                QByteArray packet;
                packet.append("BIN:");
                packet.append(encryptedChunk);
                socket_chat.send_data(packet.constData(), packet.size());

                currentOffset += bytesToSend;
                //std::this_thread::sleep_for(std::chrono::milliseconds(2));
            }
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

