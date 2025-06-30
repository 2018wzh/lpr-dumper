#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <net/sock.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/time.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/mutex.h>

#define LPR_PORT 515
#define BUFFER_SIZE 4096
#define SERVER_IP "127.0.0.1"  // Target server IP
#define SERVER_PORT 8080       // Target server port

// Module information
MODULE_LICENSE("GPL");
MODULE_AUTHOR("LPR dumper");
MODULE_DESCRIPTION("Kernel module for LPR packet dumping and forwarding");
MODULE_VERSION("1.0");

// LPR command types
#define LPR_PRINT_JOB 0x02
#define LPR_RECEIVE_CONTROL 0x02
#define LPR_RECEIVE_DATA 0x03
#define LPR_SEND_QUEUE_STATE 0x03
#define LPR_REMOVE_JOBS 0x05

// Global variables
static struct nf_hook_ops nfho;
static struct socket *server_sock = NULL;
static struct task_struct *worker_thread = NULL;
static struct mutex socket_mutex;
static bool module_running = true;

// LPR packet structure
typedef struct {
    u8 command;
    char queue_name[256];
    char data[BUFFER_SIZE];
    size_t data_len;
    long timestamp;
    __be32 src_ip;
    __be32 dst_ip;
    u16 src_port;
    u16 dst_port;
} lpr_packet_t;

// Work queue for processing packets
static struct workqueue_struct *lpr_wq;

typedef struct {
    struct work_struct work;
    lpr_packet_t packet;
} lpr_work_t;

// Convert IP address to string
static void ip_to_string(__be32 ip, char *str) {
    u8 *bytes = (u8*)&ip;
    snprintf(str, 16, "%u.%u.%u.%u", bytes[0], bytes[1], bytes[2], bytes[3]);
}

// Convert string IP to binary
static __be32 string_to_ip(const char *str) {
    u8 a, b, c, d;
    if (sscanf(str, "%hhu.%hhu.%hhu.%hhu", &a, &b, &c, &d) == 4) {
        return (a << 0) | (b << 8) | (c << 16) | (d << 24);
    }
    return 0;
}

// Connect to server
static int connect_to_server(void) {
    struct sockaddr_in server_addr;
    int ret;
    
    if (server_sock) {
        return 0; // Already connected
    }
    
    ret = sock_create(AF_INET, SOCK_STREAM, IPPROTO_TCP, &server_sock);
    if (ret < 0) {
        printk(KERN_ERR "LPR: Failed to create socket: %d\n", ret);
        return ret;
    }
    
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    server_addr.sin_addr.s_addr = string_to_ip(SERVER_IP);
    
    ret = server_sock->ops->connect(server_sock, (struct sockaddr*)&server_addr, 
                                   sizeof(server_addr), 0);
    if (ret < 0) {
        printk(KERN_ERR "LPR: Failed to connect to server: %d\n", ret);
        sock_release(server_sock);
        server_sock = NULL;
        return ret;
    }
    
    printk(KERN_INFO "LPR: Successfully connected to server %s:%d\n", 
           SERVER_IP, SERVER_PORT);
    return 0;
}

// Send data to server
static int send_to_server(const lpr_packet_t* packet) {
    struct msghdr msg;
    struct kvec iov;
    char json_data[BUFFER_SIZE * 2];
    char src_ip_str[16], dst_ip_str[16];
    int ret, json_len;
    
    mutex_lock(&socket_mutex);
    
    if (!server_sock) {
        ret = connect_to_server();
        if (ret < 0) {
            mutex_unlock(&socket_mutex);
            return ret;
        }
    }
    
    // Convert IP addresses to strings
    ip_to_string(packet->src_ip, src_ip_str);
    ip_to_string(packet->dst_ip, dst_ip_str);
    
    // Create JSON data
    json_len = snprintf(json_data, sizeof(json_data),
        "{\n"
        "  \"timestamp\": %ld,\n"
        "  \"src_ip\": \"%s\",\n"
        "  \"dst_ip\": \"%s\",\n"
        "  \"src_port\": %u,\n"
        "  \"dst_port\": %u,\n"
        "  \"lpr_command\": %u,\n"
        "  \"queue_name\": \"%.255s\",\n"
        "  \"data_length\": %zu\n"
        "}\n",
        packet->timestamp, src_ip_str, dst_ip_str,
        packet->src_port, packet->dst_port,
        packet->command, packet->queue_name,
        packet->data_len);
    
    // Prepare message
    memset(&msg, 0, sizeof(msg));
    iov.iov_base = json_data;
    iov.iov_len = json_len;
    
    ret = kernel_sendmsg(server_sock, &msg, &iov, 1, json_len);
    if (ret < 0) {
        printk(KERN_ERR "LPR: Failed to send data: %d\n", ret);
        sock_release(server_sock);
        server_sock = NULL;
    } else {
        printk(KERN_INFO "LPR: Sent packet info to server (%zu bytes)\n", 
               packet->data_len);
    }
    
    mutex_unlock(&socket_mutex);
    return ret;
}

// Parse LPR packet
static void parse_lpr_packet(const unsigned char* packet_data, size_t data_len,
                           __be32 src_ip, __be32 dst_ip,
                           u16 src_port, u16 dst_port) {
    lpr_packet_t lpr_packet;
    char src_ip_str[16], dst_ip_str[16];
    
    if (data_len == 0) return;
    
    memset(&lpr_packet, 0, sizeof(lpr_packet));
    
    // Set basic information
    lpr_packet.timestamp = ktime_get_real_seconds();
    lpr_packet.src_ip = src_ip;
    lpr_packet.dst_ip = dst_ip;
    lpr_packet.src_port = src_port;
    lpr_packet.dst_port = dst_port;
    
    // Parse LPR command
    lpr_packet.command = packet_data[0];
    
    // Convert IP addresses for printing
    ip_to_string(src_ip, src_ip_str);
    ip_to_string(dst_ip, dst_ip_str);
    
    // Parse data according to command type
    switch (lpr_packet.command) {
        case 0x01:
            printk(KERN_INFO "LPR: Command - Print waiting jobs\n");
            if (data_len > 1) {
                strncpy(lpr_packet.queue_name, (char*)(packet_data + 1), 
                       sizeof(lpr_packet.queue_name) - 1);
            }
            break;
            
        case 0x02:
            printk(KERN_INFO "LPR: Command - Receive a printer job\n");
            if (data_len > 1) {
                strncpy(lpr_packet.queue_name, (char*)(packet_data + 1), 
                       sizeof(lpr_packet.queue_name) - 1);
            }
            break;
            
        case 0x03:
            printk(KERN_INFO "LPR: Command - Send queue state\n");
            if (data_len > 1) {
                strncpy(lpr_packet.queue_name, (char*)(packet_data + 1), 
                       sizeof(lpr_packet.queue_name) - 1);
            }
            break;
            
        case 0x04:
            printk(KERN_INFO "LPR: Command - Send queue state (detailed)\n");
            if (data_len > 1) {
                strncpy(lpr_packet.queue_name, (char*)(packet_data + 1), 
                       sizeof(lpr_packet.queue_name) - 1);
            }
            break;
            
        case 0x05:
            printk(KERN_INFO "LPR: Command - Remove jobs\n");
            if (data_len > 1) {
                strncpy(lpr_packet.queue_name, (char*)(packet_data + 1), 
                       sizeof(lpr_packet.queue_name) - 1);
            }
            break;
            
        default:
            printk(KERN_INFO "LPR: Unknown command: 0x%02x\n", lpr_packet.command);
            break;
    }
    
    // Copy data
    size_t copy_len = (data_len < sizeof(lpr_packet.data)) ? 
                     data_len : sizeof(lpr_packet.data) - 1;
    memcpy(lpr_packet.data, packet_data, copy_len);
    lpr_packet.data_len = copy_len;
    
    printk(KERN_INFO "LPR: Parsed packet: %s:%u -> %s:%u, cmd=0x%02x, queue='%s', len=%zu\n",
           src_ip_str, src_port, dst_ip_str, dst_port, 
           lpr_packet.command, lpr_packet.queue_name, lpr_packet.data_len);
    
    // Send to server
    send_to_server(&lpr_packet);
}

// Work function for packet processing
static void lpr_work_handler(struct work_struct *work) {
    lpr_work_t *lpr_work = container_of(work, lpr_work_t, work);
    
    // Process the packet (already parsed, just send to server)
    send_to_server(&lpr_work->packet);
    
    kfree(lpr_work);
}

// Netfilter hook function
static unsigned int lpr_hook_func(void *priv,
                                 struct sk_buff *skb,
                                 const struct nf_hook_state *state) {
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    unsigned char *tcp_data;
    unsigned int tcp_data_len;
    u16 src_port, dst_port;
    
    if (!skb) return NF_ACCEPT;
    
    ip_header = ip_hdr(skb);
    if (!ip_header || ip_header->protocol != IPPROTO_TCP) {
        return NF_ACCEPT;
    }
    
    tcp_header = tcp_hdr(skb);
    if (!tcp_header) return NF_ACCEPT;
    
    src_port = ntohs(tcp_header->source);
    dst_port = ntohs(tcp_header->dest);
    
    // Check if it's LPR port
    if (src_port != LPR_PORT && dst_port != LPR_PORT) {
        return NF_ACCEPT;
    }
    
    // Get TCP data
    tcp_data_len = ntohs(ip_header->tot_len) - (ip_header->ihl * 4) - (tcp_header->doff * 4);
    if (tcp_data_len > 0) {
        tcp_data = (unsigned char *)tcp_header + (tcp_header->doff * 4);
        
        // Parse LPR packet
        parse_lpr_packet(tcp_data, tcp_data_len,
                        ip_header->saddr, ip_header->daddr,
                        src_port, dst_port);
    }
    
    return NF_ACCEPT;
}

// Module initialization
static int __init lpr_dumper_init(void) {
    int ret;
    
    printk(KERN_INFO "LPR: Kernel module loading...\n");
    
    // Initialize mutex
    mutex_init(&socket_mutex);
    
    // Create workqueue
    lpr_wq = create_workqueue("lpr_dumper_wq");
    if (!lpr_wq) {
        printk(KERN_ERR "LPR: Failed to create workqueue\n");
        return -ENOMEM;
    }
    
    // Setup netfilter hook
    nfho.hook = lpr_hook_func;
    nfho.hooknum = NF_INET_PRE_ROUTING;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;
    
    ret = nf_register_net_hook(&init_net, &nfho);
    if (ret) {
        printk(KERN_ERR "LPR: Failed to register netfilter hook: %d\n", ret);
        destroy_workqueue(lpr_wq);
        return ret;
    }
    
    printk(KERN_INFO "LPR: Module loaded successfully\n");
    printk(KERN_INFO "LPR: Monitoring LPR traffic on port %d\n", LPR_PORT);
    printk(KERN_INFO "LPR: Target server: %s:%d\n", SERVER_IP, SERVER_PORT);
    
    return 0;
}

// Module cleanup
static void __exit lpr_dumper_exit(void) {
    printk(KERN_INFO "LPR: Module unloading...\n");
    
    // Set running flag to false
    module_running = false;
    
    // Unregister netfilter hook
    nf_unregister_net_hook(&init_net, &nfho);
    
    // Cleanup workqueue
    if (lpr_wq) {
        flush_workqueue(lpr_wq);
        destroy_workqueue(lpr_wq);
    }
    
    // Close server connection
    mutex_lock(&socket_mutex);
    if (server_sock) {
        sock_release(server_sock);
        server_sock = NULL;
    }
    mutex_unlock(&socket_mutex);
    
    printk(KERN_INFO "LPR: Module unloaded successfully\n");
}

module_init(lpr_dumper_init);
module_exit(lpr_dumper_exit);