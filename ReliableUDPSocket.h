#pragma once

#include <cstdint>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#define close closesocket
#else
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#endif
#include <map>
#include <stdint.h>
#include <cstdio>
#include <string>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <mutex>

/* Maximum segment size, change as you see fit */
#define MAX_DATA_SIZE 512

#define MAX_CONNECTIONS 32
#define CLOSED 0
#define SYN_SENT 1
#define OPEN 2

#define SYN 0
#define SYN_ACK 1
#define ACK 2
#define DATA 3 

/* Values used for protocol ID and type. */
#define POLI_PROTOCOL_ID 42

/* Protocol control block. Used track different parameters about a connection. 
 * Will need to be extenden to solve the homework with other parameters such as
 * last_ack or status depending on how you implement your protocol. */

/* Header for segments*/
struct __attribute__((packed)) poli_tcp_hdr {
    uint8_t protocol_id;
    uint8_t conn_id;
    uint8_t type;
    uint16_t seq_num;
    uint16_t ack_num;
    uint16_t len_or_window;
};

#define MAX_SEGMENT_SIZE (MAX_DATA_SIZE + sizeof(poli_tcp_hdr))

struct packet{
    char data[MAX_SEGMENT_SIZE];
    int len;
};

class ReliableUDPSocket {
    private:
        //struct connection
        int sockfd;
        struct sockaddr_in peer_addr;

        uint16_t next_seq_num;
        uint16_t old_seq_num;
        uint16_t expected_seq_num;
        int max_window_seq;

        std::mutex con_lock;
        std::condition_variable fereastra_libera;
        std::condition_variable date_disponibile;
        std::mutex socket_mutex;

        //buffere
        std::map<uint16_t,struct packet> send_buffer;
        std::map<uint16_t,struct packet> recv_buffer;

        std::thread background_thread;
        bool is_running;

        void worker_handler();
    public:
    ReliableUDPSocket();
    ~ReliableUDPSocket();

    bool connect(const std::string&ip,uint16_t port);
    bool listen(uint16_t port);

    int send_data(const char* buffer,int len);
    int recv_data(char*buffer,int len);

    void enable_broadcast();
    void send_broadcast(const char* data, int length, int port);
};



