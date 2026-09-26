#include "ReliableUDPSocket.h"
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#define close closesocket
#else
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#endif
#include <cstring>
#include <iostream>

// Constructor

ReliableUDPSocket::ReliableUDPSocket()
{
#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif
    sockfd = -1;
    next_seq_num = 0;
    old_seq_num = 0;
    expected_seq_num = 0;
    max_window_seq = 200;
    is_running = false;
}

// Destructor
ReliableUDPSocket::~ReliableUDPSocket()
{
    is_running = false;
    fereastra_libera.notify_all();
    date_disponibile.notify_all();

    if (background_thread.joinable())
    {
        background_thread.join();
    }

    if (sockfd >= 0)
    {
        close(sockfd);
    }
#ifdef _WIN32
    WSACleanup();
#endif
}

// Clientul initiaza conexiune
bool ReliableUDPSocket::connect(const std::string &ip, uint16_t port)
{
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
        return false;

    // timeout pentru receptie
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 500000;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    // adresa serverului
    memset(&peer_addr, 0, sizeof(peer_addr));
    peer_addr.sin_family = AF_INET;
    peer_addr.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &peer_addr.sin_addr);

    // three-way handshake
    poli_tcp_hdr syn_hdr = {};
    syn_hdr.protocol_id = POLI_PROTOCOL_ID;
    syn_hdr.type = SYN;
    syn_hdr.seq_num = 0;

    char buf[MAX_SEGMENT_SIZE];
    bool connected = false;

    std::cout << "[Client] Trimit SYN spre " << ip << ":" << port << "...\n";

    while (!connected)
    {
        sendto(sockfd, (const char*)&syn_hdr, sizeof(syn_hdr), 0, (struct sockaddr *)&peer_addr, sizeof(peer_addr));

        socklen_t len = sizeof(peer_addr);
        int rc = recvfrom(sockfd, buf, sizeof(buf), 0, (struct sockaddr *)&peer_addr, &len);

        if (rc > 0)
        {
            poli_tcp_hdr *header_recv = (poli_tcp_hdr *)buf;
            if (header_recv->type == SYN_ACK)
            {
                // receive ACK
                uint16_t port_recv = *(uint16_t *)(buf + sizeof(poli_tcp_hdr));
                peer_addr.sin_port = port_recv;
                connected = true;
            }
        }
    }

    // SEND ACK
    syn_hdr.type = ACK;
    sendto(sockfd, (const char*)&syn_hdr, sizeof(syn_hdr), 0, (struct sockaddr *)&peer_addr, sizeof(peer_addr));
    std::cout << "[Client] Conexiune stabilita!\n";
    is_running = true;
    background_thread = std::thread(&ReliableUDPSocket::worker_handler, this);
    return true;
}

bool ReliableUDPSocket::listen(uint16_t port)
{

    int listen_fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in serv_addr{};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(port);
    if(bind(listen_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr))){
        close(listen_fd);
        return false;
    }

    char buf[MAX_SEGMENT_SIZE];
    socklen_t len = sizeof(peer_addr);
    std::cout << "[Server] Aștept SYN pe portul " << port << "...\n";

    // asteptare pachet SYN
    while (true)
    {
        recvfrom(listen_fd, buf, sizeof(buf), 0, (struct sockaddr *)&peer_addr, &len);
        poli_tcp_hdr *hdr = (poli_tcp_hdr *)buf;
        if (hdr->type == SYN)
            break;
    }

    std::cout << "[Server] Primit SYN, creez socket dedicat...\n";

    // creare socket pentru conexiune specifica
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in new_serv_addr{};
    new_serv_addr.sin_family = AF_INET;
    new_serv_addr.sin_addr.s_addr = INADDR_ANY;
    new_serv_addr.sin_port = 0; // alegere automat port liber
    bind(sockfd, (struct sockaddr *)&new_serv_addr, sizeof(new_serv_addr));

    socklen_t new_len = sizeof(new_serv_addr);
    getsockname(sockfd, (struct sockaddr *)&new_serv_addr, &new_len);

    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 500000;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    // send SYN-ACK with new port

    poli_tcp_hdr syn_ack_hdr = {};
    syn_ack_hdr.protocol_id = POLI_PROTOCOL_ID;
    syn_ack_hdr.type = SYN_ACK;

    char syn_ack_buf[sizeof(poli_tcp_hdr) + sizeof(uint16_t)];
    memcpy(syn_ack_buf, &syn_ack_hdr, sizeof(poli_tcp_hdr));
    memcpy(syn_ack_buf + sizeof(poli_tcp_hdr), &new_serv_addr.sin_port, sizeof(uint16_t));

    // wait receive ACK

    bool ack_recv = false;
    while (!ack_recv)
    {
        sendto(listen_fd, syn_ack_buf, sizeof(syn_ack_buf), 0, (struct sockaddr *)&peer_addr, len);
        int rc = recvfrom(sockfd, buf, sizeof(buf), 0, (struct sockaddr *)&peer_addr, &len);
        if (rc > 0)
        {
            poli_tcp_hdr *hdr = (poli_tcp_hdr *)buf;
            if (hdr->type == ACK || hdr->type == DATA)
                ack_recv = true;
        }
    }
    // clean listen socket
    close(listen_fd);

    std::cout << "[Server] Conexiune stabilită cu succes pe noul port!\n";
    is_running = true;
    background_thread = std::thread(&ReliableUDPSocket::worker_handler, this);
    return true;
}

int ReliableUDPSocket::send_data(const char *buffer, int len)
{
    std::unique_lock<std::mutex> lock(con_lock);

    // if windows is full, thread sleep

    fereastra_libera.wait(lock, [this]()
                          { return (next_seq_num - old_seq_num) < max_window_seq; });

    // packet(header+data)

    char send_buf[MAX_SEGMENT_SIZE];
    poli_tcp_hdr *hdr = (poli_tcp_hdr *)send_buf;
    hdr->protocol_id = POLI_PROTOCOL_ID;
    hdr->type = DATA;
    hdr->seq_num = next_seq_num;
    hdr->len_or_window = len;

    memcpy(send_buf + sizeof(poli_tcp_hdr), buffer, len);

    // save packet in buffer for retransmission
    struct packet pkt;
    pkt.len = sizeof(poli_tcp_hdr) + len;
    memcpy(pkt.data, send_buf, pkt.len);
    send_buffer[next_seq_num] = pkt;

    // send
    sendto(sockfd, send_buf, pkt.len, 0, (struct sockaddr *)&peer_addr, sizeof(peer_addr));
    next_seq_num++;
    return len;
}

int ReliableUDPSocket::recv_data(char *buffer, int len)
{
    std::unique_lock<std::mutex> lock(con_lock);

    date_disponibile.wait(lock, [this]()
                          { return recv_buffer.find(expected_seq_num) != recv_buffer.end(); });

    struct packet pkt = recv_buffer[expected_seq_num];
    recv_buffer.erase(expected_seq_num);

    poli_tcp_hdr *hdr = (poli_tcp_hdr *)pkt.data;
    int data_len = hdr->len_or_window;

    // copy in user buffer
    memcpy(buffer, pkt.data + sizeof(poli_tcp_hdr), data_len);
    expected_seq_num++;
    return data_len;
}

void ReliableUDPSocket::worker_handler()
{
    char buf[MAX_SEGMENT_SIZE];

    while (is_running)
    {
        socklen_t len = sizeof(peer_addr);

        // wait packet
        int rc = recvfrom(sockfd, buf, sizeof(buf), 0, (struct sockaddr *)&peer_addr, &len);

        // block resources
        std::unique_lock<std::mutex> lock(con_lock);

        if (rc > 0)
        {
            poli_tcp_hdr *hdr = (poli_tcp_hdr *)buf;

            if (hdr->type == ACK)
            {
                // clear the window
                uint16_t acked_seq = hdr->ack_num;
                if (send_buffer.find(acked_seq) != send_buffer.end())
                {
                    send_buffer.erase(acked_seq);

                    if (old_seq_num == acked_seq)
                    {
                        old_seq_num++;
                        while (send_buffer.find(old_seq_num) == send_buffer.end() && old_seq_num < next_seq_num)
                        {
                            old_seq_num++;
                        }
                    }
                    fereastra_libera.notify_all();
                }
            }
            else if (hdr->type == DATA)
            {
                // receive data,send ACK
                uint16_t seq = hdr->seq_num;

                poli_tcp_hdr ack_hdr = {};
                ack_hdr.protocol_id = POLI_PROTOCOL_ID;
                ack_hdr.type = ACK;
                ack_hdr.ack_num = seq;
                sendto(sockfd, (const char*)&ack_hdr, sizeof(ack_hdr), 0, (struct sockaddr *)&peer_addr, sizeof(peer_addr));

                // save data
                if (seq >= expected_seq_num && recv_buffer.find(seq) == recv_buffer.end())
                {
                    struct packet pkt;
                    pkt.len = rc;
                    memcpy(pkt.data, buf, rc);
                    recv_buffer[seq] = pkt;

                    if (seq == expected_seq_num)
                    {
                        date_disponibile.notify_all();
                    }
                }
            }
        }
        else
        {
            // rc <0, timeout expired
            if (!send_buffer.empty())
            {
                if (send_buffer.find(old_seq_num) != send_buffer.end())
                {
                    struct packet &pkt = send_buffer[old_seq_num];
                    sendto(sockfd, pkt.data, pkt.len, 0, (struct sockaddr *)&peer_addr, sizeof(peer_addr));
                }
            }
        }
    }
}

// void ReliableUDPSocket::enable_broadcast(){
//     int broadcastPermission = 1;

//     if (setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, (char*)&broadcastPermission,sizeof(broadcastPermission))<0) {

//     }
// }

// void ReliableUDPSocket::send_broadcast(const char* data, int length, int port){
//     struct sockaddr_in broadcastAddr;
//     broadcastAddr.sin_family =  AF_INET;
//     broadcastAddr.sin_port =  htons(port);
//     broadcastAddr.sin_addr.s_addr = inet_addr("255.255.255.255");

//     sendto(sockfd, data, length, 0, (struct sockaddr*)&broadcastAddr, sizeof(broadcastAddr));
// }
