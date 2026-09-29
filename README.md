# P2P Secure LAN Messenger 🛡️

A decentralized, peer-to-peer desktop application for encrypted local area network (LAN) communication and binary file transfers. Built completely from scratch in C++ using a custom Reliable UDP protocol and native Qt6 Widgets.

This project demonstrates low-level networking, custom packet architectures, concurrent programming, and applied cryptography.

## 🚀 Key Features

* **Custom Reliable UDP Protocol:** Implements a stateful ARQ (Automatic Repeat reQuest) protocol over standard UDP sockets. Includes a custom 3-way handshake (SYN, SYN-ACK, ACK), sliding windows for flow control, packet acknowledgment, and automatic retransmission of lost packets.
* **LAN Auto-Discovery Radar:** Uses UDP broadcast datagrams on port 8081 (`DISCOVER:`) to automatically find and connect to available peers on the local network without requiring manual IP configuration.
* **End-to-End Encryption (E2EE):**
    * Cryptographic keys are securely negotiated upon connection via the **Diffie-Hellman Key Exchange** algorithm.
    * All subsequent network traffic (text and binary files) is symmetrically encrypted in-memory using a custom XOR cipher before leaving the socket.
* **Multithreaded Architecture:** The network listening engine and file-transfer loops run on isolated detached background threads (`std::thread`), ensuring the Qt Graphical User Interface remains completely fluid and responsive during large file uploads.
* **Chunked Binary Transfers:** Supports sending images and files by streaming binary data in secure 256-byte chunks (`BIN:` packets), allowing for memory-efficient processing of larger files.

## 🛠️ Tech Stack

* **Language:** C++17
* **Framework:** Qt6 (Qt Widgets, Qt Network)
* **Build System:** CMake / qmake
* **Networking:** POSIX Sockets / Winsock2 (Cross-platform compatibility), `QUdpSocket`

## 🧠 System Architecture

1. **Node Unification:** The application is symmetric. Upon startup, it attempts to bind on port 8080 as a Host. If the port is busy, it cleanly falls back to Client mode, awaiting radar signals to initiate connection.
2. **Security Negotiation:** Once the UDP tunnel is established, both nodes generate private random secrets and compute modulo operations over prime `P = 2147483647` and base `G = 16807` to calculate the shared session key.
3. **Thread Safety:** The network worker signals the UI thread asynchronously via Qt's `QMetaObject::invokeMethod` and `Qt::QueuedConnection` to render decrypted text and update file transfer states safely.

## 💻 Build Instructions

**Prerequisites:** You need Qt Creator and Qt6 framework installed on your system.

1. Clone the repository:
    ```bash 
    git clone (https://github.com/yourusername/P2PMessenger.git)
    ```
2. Open the CMakeLists or .pro file in Qt Creator.
3. Configure the project for your local compiler.
4. Build and Run.
5. Launch two instances of the application on the same machine or on two different machines connected to the same Wi-Fi network.
