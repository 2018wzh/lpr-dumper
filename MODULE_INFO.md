# LPR dumper Kernel Module

## Module Information
- **Name**: lpr_dumper
- **Version**: 1.0
- **License**: GPL
- **Author**: LPR dumper
- **Description**: Kernel module for LPR packet dumping and forwarding

## Kernel API Usage

### Netfilter Framework
- Uses `nf_register_net_hook()` and `nf_unregister_net_hook()`
- Hook point: `NF_INET_PRE_ROUTING`
- Priority: `NF_IP_PRI_FIRST`

### Kernel Socket API
- `sock_create()` - Create kernel socket
- `kernel_sendmsg()` - Send data through socket
- `sock_release()` - Release socket resources

### Memory Management
- `kmalloc()` / `kfree()` - Kernel memory allocation
- `GFP_KERNEL` flag for normal allocations

### Synchronization
- `mutex_init()` - Initialize mutex
- `mutex_lock()` / `mutex_unlock()` - Protect shared resources

### Work Queues
- `create_workqueue()` - Create dedicated workqueue
- `queue_work()` - Schedule work
- `flush_workqueue()` / `destroy_workqueue()` - Cleanup

## Module Parameters

The module currently uses compile-time constants. To make it configurable, you can add module parameters:

```c
static char* server_ip = "127.0.0.1";
static int server_port = 8080;

module_param(server_ip, charp, 0644);
MODULE_PARM_DESC(server_ip, "Target server IP address");

module_param(server_port, int, 0644);
MODULE_PARM_DESC(server_port, "Target server port");
```

Then load with parameters:
```bash
sudo insmod lpr_dumper.ko server_ip="192.168.1.100" server_port=9090
```

## Debugging

### Enable Debug Output
Add debug parameter to module:
```c
static bool debug = false;
module_param(debug, bool, 0644);
MODULE_PARM_DESC(debug, "Enable debug output");

#define dprintk(fmt, args...) \
    do { if (debug) printk(KERN_DEBUG "LPR: " fmt, ##args); } while (0)
```

### Kernel Log Levels
- `KERN_EMERG` - Emergency messages
- `KERN_ALERT` - Alert messages
- `KERN_CRIT` - Critical messages
- `KERN_ERR` - Error messages
- `KERN_WARNING` - Warning messages
- `KERN_NOTICE` - Notice messages
- `KERN_INFO` - Information messages
- `KERN_DEBUG` - Debug messages

## Performance Considerations

### Packet Processing
- Keep hook function lightweight
- Use work queues for heavy processing
- Avoid sleeping in hook context

### Memory Usage
- Monitor kernel memory usage with `/proc/meminfo`
- Use appropriate GFP flags for allocation context
- Free resources promptly

### Network Impact
- Minimal packet processing delay
- Non-blocking network operations
- Proper error handling for network failures

## Security Implications

### Kernel Space Access
- Full system access and privileges
- Can crash system if not properly written
- Memory corruption can affect entire system

### Network Monitoring
- Captures all LPR traffic on the system
- May contain sensitive print job data
- Ensure proper access controls

### Data Transmission
- Unencrypted JSON data transmission
- Consider adding encryption for sensitive environments
- Validate server connections

## Extension Ideas

### Configuration Interface
- Add `/proc` or `/sys` interface for runtime configuration
- Support for multiple target servers
- Dynamic filter configuration

### Enhanced Filtering
- Filter by source/destination IP ranges
- Support for different printer protocols
- Content-based filtering

### Data Processing
- On-the-fly data compression
- Encryption before transmission
- Local logging capabilities

## Compatibility

### Kernel Versions
- Tested on Linux 5.x kernels
- May require modifications for older kernels
- Check API compatibility for specific versions

### Architecture Support
- x86_64 (tested)
- ARM64 (should work)
- Other architectures may need testing

## Testing

### Unit Testing
```bash
# Load module
sudo insmod lpr_dumper.ko

# Generate test traffic (if available)
# Check kernel logs
dmesg | grep LPR

# Unload module
sudo rmmod lpr_dumper
```

### Integration Testing
- Test with real LPR traffic
- Verify server receives correct JSON data
- Test module loading/unloading cycles
- Monitor system stability

## Known Limitations

1. **No user-space configuration**: Requires recompilation for configuration changes
2. **No encryption**: Data sent in plain text
3. **Single server**: Only supports one target server
4. **No persistence**: Settings lost on module unload
5. **No rate limiting**: May overwhelm target server

## Future Improvements

1. Add module parameters for runtime configuration
2. Implement encryption for data transmission
3. Add support for multiple target servers
4. Create user-space configuration utility
5. Add comprehensive error handling and recovery
6. Implement rate limiting and flow control
