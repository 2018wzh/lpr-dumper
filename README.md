# LPR数据包解析器

这是一个用C语言编写的Linux系统LPR（Line Printer Remote）数据包捕获和解析程序。该程序可以监听网络接口上的LPR流量，解析数据包内容，并通过TCP连接将解析结果发送到指定服务器。

## 功能特性

- 实时捕获网络接口上的LPR数据包（端口515）
- 解析LPR协议命令和数据
- 提取源/目标IP地址和端口信息
- 将解析结果以JSON格式发送到远程服务器
- 支持多种LPR命令类型识别
- 优雅的信号处理和资源清理

## 依赖要求

- Linux操作系统
- libpcap开发库
- gcc编译器
- root权限（用于网络数据包捕获）

## 编译安装

### 1. 安装依赖

**Ubuntu/Debian系统:**
```bash
sudo apt-get update
sudo apt-get install libpcap-dev gcc make
```

**CentOS/RHEL系统:**
```bash
sudo yum install libpcap-devel gcc make
# 或者对于较新版本
sudo dnf install libpcap-devel gcc make
```

### 2. 编译程序

```bash
make
```

或者手动编译：
```bash
gcc -Wall -Wextra -std=c99 -O2 -o lpr-parser main.c -lpcap
```

## 使用方法

### 基本用法

```bash
# 使用默认网卡监听LPR数据包
sudo ./lpr-parser

# 指定网卡接口
sudo ./lpr-parser eth0
```

### 配置说明

在运行前，请修改 `main.c` 中的服务器配置：

```c
#define SERVER_IP "127.0.0.1"  // 修改为目标服务器IP
#define SERVER_PORT 8080       // 修改为目标服务器端口
```

## 程序输出

程序会实时显示捕获到的LPR数据包信息，包括：
- 时间戳
- 源IP和端口
- 目标IP和端口
- LPR命令类型
- 队列名称
- 数据长度

示例输出：
```
LPR数据包解析器启动...
使用网卡: eth0
开始监听LPR数据包...
过滤器: tcp port 515
目标服务器: 192.168.1.100:8080
按 Ctrl+C 退出

LPR命令: 接收打印作业
解析LPR数据包: 192.168.1.10:12345 -> 192.168.1.20:515, 命令=0x02, 队列='printer1', 数据长度=1024
已发送LPR数据包信息到服务器 (1024字节)
```

## JSON数据格式

发送到服务器的数据采用JSON格式：

```json
{
  "timestamp": "2025-06-30 10:30:45",
  "src_ip": "192.168.1.10",
  "dst_ip": "192.168.1.20",
  "src_port": 12345,
  "dst_port": 515,
  "lpr_command": 2,
  "queue_name": "printer1",
  "data_length": 1024,
  "data": "打印作业数据内容..."
}
```

## LPR命令类型

程序识别以下LPR命令：

- `0x01`: 打印等待作业
- `0x02`: 接收打印作业
- `0x03`: 发送队列状态
- `0x04`: 发送队列状态（详细）
- `0x05`: 删除作业

## 注意事项

1. **权限要求**: 程序需要root权限才能捕获网络数据包
2. **网络接口**: 确保指定的网络接口存在且处于活动状态
3. **防火墙**: 确保能够连接到目标服务器
4. **服务器连接**: 程序会自动重连断开的服务器连接

## 故障排除

### 常见问题

1. **权限错误**
   ```
   无法打开网卡: Operation not permitted
   ```
   解决方案: 使用 `sudo` 运行程序

2. **找不到网卡**
   ```
   无法找到默认网卡
   ```
   解决方案: 手动指定网卡名称，如 `sudo ./lpr-parser eth0`

3. **连接服务器失败**
   ```
   连接服务器失败: Connection refused
   ```
   解决方案: 检查服务器IP和端口配置，确保服务器正在运行

### 调试模式

可以修改代码中的打印语句来获得更详细的调试信息。

## 安全考虑

- 程序会捕获网络流量，请确保符合当地法律法规
- 建议在测试环境中使用
- 传输的数据可能包含敏感信息，请确保服务器连接安全

## 清理

```bash
make clean
```

## 许可证

本程序仅供学习和测试使用。
