#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <errno.h>
#include <time.h>
#include <signal.h>

#define LPR_PORT 515
#define BUFFER_SIZE 4096
#define SERVER_IP "127.0.0.1"  // Target server IP
#define SERVER_PORT 8080       // Target server port

// LPR command types
#define LPR_PRINT_JOB 0x02
#define LPR_RECEIVE_CONTROL 0x02
#define LPR_RECEIVE_DATA 0x03
#define LPR_SEND_QUEUE_STATE 0x03
#define LPR_REMOVE_JOBS 0x05

// Global variables
static volatile int running = 1;
static int server_socket = -1;

// LPR packet structure
typedef struct {
    uint8_t command;
    char queue_name[256];
    char data[BUFFER_SIZE];
    size_t data_len;
    time_t timestamp;
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    uint16_t src_port;
    uint16_t dst_port;
} lpr_packet_t;

// Signal handler function
void signal_handler(int sig) {
    printf("\nCaught signal %d, exiting...\n", sig);
    running = 0;
}

// Connect to server
int connect_to_server() {
    int sock;
    struct sockaddr_in server_addr;
    
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Failed to create socket");
        return -1;
    }
    
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    
    if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
        perror("Invalid IP address");
        close(sock);
        return -1;
    }
    
    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Failed to connect to server");
        close(sock);
        return -1;
    }
    
    printf("Successfully connected to server %s:%d\n", SERVER_IP, SERVER_PORT);
    return sock;
}

// Send data to server
int send_to_server(const lpr_packet_t* packet) {
    if (server_socket < 0) {
        server_socket = connect_to_server();
        if (server_socket < 0) {
            return -1;
        }
    }
    
    // Construct JSON formatted data
    char json_data[BUFFER_SIZE * 2];
    char time_str[64];
    struct tm* tm_info = localtime(&packet->timestamp);
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
    
    // Simple escape processing for data
    char escaped_data[BUFFER_SIZE * 2];
    const char* src = packet->data;
    char* dst = escaped_data;
    size_t i = 0;
    
    while (i < packet->data_len && dst < escaped_data + sizeof(escaped_data) - 2) {
        if (*src == '"' || *src == '\\') {
            *dst++ = '\\';
        }
        if (*src >= 32 && *src <= 126) {  // Printable characters
            *dst++ = *src;
        } else {
            // Non-printable characters in hex format
            snprintf(dst, 5, "\\x%02x", (unsigned char)*src);
            dst += 4;
        }
        src++;
        i++;
    }
    *dst = '\0';
    
    int json_len = snprintf(json_data, sizeof(json_data),
        "{\n"
        "  \"timestamp\": \"%s\",\n"
        "  \"src_ip\": \"%s\",\n"
        "  \"dst_ip\": \"%s\",\n"
        "  \"src_port\": %u,\n"
        "  \"dst_port\": %u,\n"
        "  \"lpr_command\": %u,\n"
        "  \"queue_name\": \"%s\",\n"
        "  \"data_length\": %zu,\n"
        "  \"data\": \"%s\"\n"
        "}\n",
        time_str, packet->src_ip, packet->dst_ip,
        packet->src_port, packet->dst_port,
        packet->command, packet->queue_name,
        packet->data_len, escaped_data);
    
    if (send(server_socket, json_data, json_len, 0) < 0) {
        perror("Failed to send data");
        close(server_socket);
        server_socket = -1;
        return -1;
    }
    
    printf("Sent LPR packet info to server (%zu bytes)\n", packet->data_len);
    return 0;
}

// Parse LPR packet
void parse_lpr_packet(const u_char* packet_data, size_t data_len, 
                     const char* src_ip, const char* dst_ip,
                     uint16_t src_port, uint16_t dst_port) {
    
    if (data_len == 0) return;
    
    lpr_packet_t lpr_packet;
    memset(&lpr_packet, 0, sizeof(lpr_packet));
    
    // Set basic information
    lpr_packet.timestamp = time(NULL);
    strcpy(lpr_packet.src_ip, src_ip);
    strcpy(lpr_packet.dst_ip, dst_ip);
    lpr_packet.src_port = src_port;
    lpr_packet.dst_port = dst_port;
    
    // Parse LPR command
    lpr_packet.command = packet_data[0];
    
    // Parse data according to command type
    switch (lpr_packet.command) {
        case 0x01: // Print waiting jobs
            printf("LPR Command: Print waiting jobs\n");
            if (data_len > 1) {
                strncpy(lpr_packet.queue_name, (char*)(packet_data + 1), 
                       sizeof(lpr_packet.queue_name) - 1);
            }
            break;
            
        case 0x02: // Receive a printer job
            printf("LPR Command: Receive a printer job\n");
            if (data_len > 1) {
                strncpy(lpr_packet.queue_name, (char*)(packet_data + 1), 
                       sizeof(lpr_packet.queue_name) - 1);
            }
            break;
            
        case 0x03: // Send queue state
            printf("LPR Command: Send queue state\n");
            if (data_len > 1) {
                strncpy(lpr_packet.queue_name, (char*)(packet_data + 1), 
                       sizeof(lpr_packet.queue_name) - 1);
            }
            break;
            
        case 0x04: // Send queue state (long)
            printf("LPR Command: Send queue state (detailed)\n");
            if (data_len > 1) {
                strncpy(lpr_packet.queue_name, (char*)(packet_data + 1), 
                       sizeof(lpr_packet.queue_name) - 1);
            }
            break;
            
        case 0x05: // Remove jobs
            printf("LPR Command: Remove jobs\n");
            if (data_len > 1) {
                strncpy(lpr_packet.queue_name, (char*)(packet_data + 1), 
                       sizeof(lpr_packet.queue_name) - 1);
            }
            break;
            
        default:
            printf("Unknown LPR command: 0x%02x\n", lpr_packet.command);
            break;
    }
    
    // Copy data
    size_t copy_len = (data_len < sizeof(lpr_packet.data)) ? 
                     data_len : sizeof(lpr_packet.data) - 1;
    memcpy(lpr_packet.data, packet_data, copy_len);
    lpr_packet.data_len = copy_len;
    
    printf("Parsed LPR packet: %s:%u -> %s:%u, command=0x%02x, queue='%s', data_len=%zu\n",
           src_ip, src_port, dst_ip, dst_port, 
           lpr_packet.command, lpr_packet.queue_name, lpr_packet.data_len);
    
    // Send to server
    send_to_server(&lpr_packet);
}

// Packet handler callback function
void packet_handler(u_char* user_data, const struct pcap_pkthdr* pkthdr, 
                   const u_char* packet) {
    
    // Parse Ethernet header
    struct iphdr* ip_header = (struct iphdr*)(packet + 14); // Skip Ethernet header
    
    // Check if it's TCP protocol
    if (ip_header->protocol != IPPROTO_TCP) {
        return;
    }
    
    // Parse TCP header
    struct tcphdr* tcp_header = (struct tcphdr*)((u_char*)ip_header + (ip_header->ihl * 4));
    
    uint16_t src_port = ntohs(tcp_header->source);
    uint16_t dst_port = ntohs(tcp_header->dest);
    
    // Check if it's LPR port
    if (src_port != LPR_PORT && dst_port != LPR_PORT) {
        return;
    }
    
    // Get IP addresses
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_header->saddr, src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &ip_header->daddr, dst_ip, INET_ADDRSTRLEN);
    
    // Calculate TCP data offset
    int tcp_header_len = tcp_header->doff * 4;
    int ip_header_len = ip_header->ihl * 4;
    int total_header_len = 14 + ip_header_len + tcp_header_len; // Ethernet + IP + TCP
    
    // Get TCP data
    if (pkthdr->caplen > total_header_len) {
        const u_char* tcp_data = packet + total_header_len;
        size_t tcp_data_len = pkthdr->caplen - total_header_len;
        
        if (tcp_data_len > 0) {
            parse_lpr_packet(tcp_data, tcp_data_len, src_ip, dst_ip, src_port, dst_port);
        }
    }
}

int main(int argc, char* argv[]) {
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    char* device = NULL;
    struct bpf_program filter;
    char filter_exp[] = "tcp port 515";  // LPR port filter
    bpf_u_int32 net, mask;
    
    printf("LPR Packet Parser started...\n");
    
    // Register signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // If no device specified, automatically select default device
    if (argc > 1) {
        device = argv[1];
    } else {
        device = pcap_lookupdev(errbuf);
        if (device == NULL) {
            fprintf(stderr, "Cannot find default device: %s\n", errbuf);
            return 1;
        }
    }
    
    printf("Using device: %s\n", device);
    
    // Get network information
    if (pcap_lookupnet(device, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Cannot get device information: %s\n", errbuf);
        net = 0;
        mask = 0;
    }
    
    // Open device for capture
    handle = pcap_open_live(device, BUFFER_SIZE, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Cannot open device %s: %s\n", device, errbuf);
        return 1;
    }
    
    // Check data link layer type
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Device %s does not support Ethernet\n", device);
        pcap_close(handle);
        return 1;
    }
    
    // Compile and apply filter
    if (pcap_compile(handle, &filter, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Cannot compile filter %s: %s\n", filter_exp, pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }
    
    if (pcap_setfilter(handle, &filter) == -1) {
        fprintf(stderr, "Cannot set filter %s: %s\n", filter_exp, pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }
    
    printf("Started listening for LPR packets...\n");
    printf("Filter: %s\n", filter_exp);
    printf("Target server: %s:%d\n", SERVER_IP, SERVER_PORT);
    printf("Press Ctrl+C to exit\n\n");
    
    // Start capturing packets
    while (running) {
        int result = pcap_loop(handle, 1, packet_handler, NULL);
        if (result == -1) {
            fprintf(stderr, "pcap_loop error: %s\n", pcap_geterr(handle));
            break;
        } else if (result == -2) {
            // pcap_breakloop was called
            break;
        }
    }
    
    // Cleanup resources
    printf("\nCleaning up resources...\n");
    pcap_freecode(&filter);
    pcap_close(handle);
    
    if (server_socket >= 0) {
        close(server_socket);
    }
    
    printf("Program exited\n");
    return 0;
}