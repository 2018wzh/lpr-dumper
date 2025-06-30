# LPR Kernel Module dumper

This is a Linux kernel module written in C for capturing and dumping LPR (Line Printer Remote) packets. The module operates in kernel space, using netfilter hooks to intercept LPR traffic and forwards the parsed results to a specified server via TCP connection.

## Features

- Real-time LPR packet capture using netfilter hooks (port 515)
- Kernel-space LPR protocol dumping and command recognition
- Extract source/destination IP addresses and port information
- Send parsed results in JSON format to remote server
- Support for multiple LPR command types identification
- Kernel module with proper initialization and cleanup

## Requirements

- Linux operating system with kernel headers
- GCC compiler and build tools
- Root privileges (for module loading/unloading)
- Target server to receive parsed data

## Build and Installation

### 1. Install Dependencies

**Ubuntu/Debian systems:**
```bash
sudo apt-get update
sudo apt-get install linux-headers-$(uname -r) build-essential
```

**CentOS/RHEL systems:**
```bash
sudo yum install kernel-devel-$(uname -r) gcc make
# or for newer versions
sudo dnf install kernel-devel-$(uname -r) gcc make
```

### 2. Build the Module

```bash
make
```

This will compile the kernel module and create `lpr_dumper.ko`.

## Usage

### Loading the Module

```bash
# Load the module
sudo make load
# or manually
sudo insmod lpr_dumper.ko
```

### Configuration

Before loading the module, modify the server configuration in `main.c`:

```c
#define SERVER_IP "127.0.0.1"  // Change to target server IP
#define SERVER_PORT 8080       // Change to target server port
```

### Module Operations

```bash
# Check if module is loaded
lsmod | grep lpr_dumper

# View module information
make info

# Check kernel messages (module output)
make logs
# or
dmesg | tail -20

# Unload the module
sudo make unload
# or manually
sudo rmmod lpr_dumper
```

## Module Output

The module outputs information to kernel log, which can be viewed with `dmesg`:

```
LPR: Module loaded successfully
LPR: Monitoring LPR traffic on port 515
LPR: Target server: 192.168.1.100:8080
LPR: Command - Receive a printer job
LPR: Parsed packet: 192.168.1.10:12345 -> 192.168.1.20:515, cmd=0x02, queue='printer1', len=1024
LPR: Successfully connected to server 192.168.1.100:8080
LPR: Sent packet info to server (1024 bytes)
```

## JSON Data Format

Data sent to the server uses JSON format:

```json
{
  "timestamp": 1719734445,
  "src_ip": "192.168.1.10",
  "dst_ip": "192.168.1.20",
  "src_port": 12345,
  "dst_port": 515,
  "lpr_command": 2,
  "queue_name": "printer1",
  "data_length": 1024
}
```

## Supported LPR Commands

The module recognizes the following LPR commands:

- `0x01`: Print waiting jobs
- `0x02`: Receive a printer job
- `0x03`: Send queue state
- `0x04`: Send queue state (detailed)
- `0x05`: Remove jobs

## Architecture

### Netfilter Hook
- Uses `NF_INET_PRE_ROUTING` hook to capture packets early in the network stack
- Filters TCP packets on port 515 (LPR)
- Operates with `NF_IP_PRI_FIRST` priority

### Kernel Socket API
- Creates TCP socket using `sock_create()`
- Uses `kernel_sendmsg()` for data transmission
- Automatic reconnection on connection failure

### Work Queue
- Uses kernel workqueue for non-blocking packet processing
- Ensures network operations don't block packet processing

## Important Notes

1. **Kernel Space**: Module runs in kernel space with kernel APIs
2. **Root Privileges**: Requires root to load/unload modules
3. **System Impact**: Monitor system performance when loaded
4. **Memory Management**: Uses kernel memory allocation (`kmalloc`/`kfree`)
5. **Network Security**: Ensure target server connection is secure

## Troubleshooting

### Common Issues

1. **Module compilation failed**
   ```
   make: *** No rule to make target 'modules'
   ```
   Solution: Install kernel headers for your kernel version

2. **Module loading failed**
   ```
   insmod: ERROR: could not insert module
   ```
   Solution: Check `dmesg` for specific error messages

3. **No packets captured**
   ```
   Module loaded but no LPR traffic detected
   ```
   Solution: Verify LPR traffic is present on the network

4. **Server connection failed**
   ```
   LPR: Failed to connect to server: -111
   ```
   Solution: Check server IP/port configuration and network connectivity

### Debug Commands

```bash
# Check module status
cat /proc/modules | grep lpr_dumper

# Monitor kernel messages in real-time
sudo dmesg -w

# Check network connections
ss -tuln | grep 8080
```

## Clean Up

```bash
# Clean build files
make clean

# Remove module if loaded
sudo make unload
```

## Security Considerations

- Module operates with kernel privileges
- Network traffic capture may contain sensitive information
- Ensure compliance with local laws and regulations
- Use in controlled environments for testing
- Secure communication with target server

## License

This kernel module is provided for educational and testing purposes under GPL license.
