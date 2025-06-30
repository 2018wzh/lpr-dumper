#!/usr/bin/env python3
"""
简单的TCP服务器，用于接收LPR解析器发送的数据
使用方法: python3 test_server.py [port]
"""

import socket
import sys
import json
import threading
from datetime import datetime

def handle_client(client_socket, addr):
    """处理客户端连接"""
    print(f"[{datetime.now()}] 客户端连接: {addr}")
    
    try:
        while True:
            # 接收数据
            data = client_socket.recv(4096)
            if not data:
                break
            
            try:
                # 尝试解析JSON数据
                json_data = json.loads(data.decode('utf-8'))
                print(f"\n[{datetime.now()}] 收到LPR数据包:")
                print(f"  时间: {json_data.get('timestamp')}")
                print(f"  源地址: {json_data.get('src_ip')}:{json_data.get('src_port')}")
                print(f"  目标地址: {json_data.get('dst_ip')}:{json_data.get('dst_port')}")
                print(f"  LPR命令: 0x{json_data.get('lpr_command'):02x}")
                print(f"  队列名称: {json_data.get('queue_name')}")
                print(f"  数据长度: {json_data.get('data_length')} 字节")
                print(f"  数据内容: {json_data.get('data')[:100]}...")  # 只显示前100个字符
                print("-" * 50)
                
            except json.JSONDecodeError:
                # 如果不是JSON格式，直接显示原始数据
                print(f"\n[{datetime.now()}] 收到原始数据 ({len(data)} 字节):")
                print(data.decode('utf-8', errors='ignore')[:200] + "...")
                print("-" * 50)
                
    except ConnectionResetError:
        print(f"[{datetime.now()}] 客户端 {addr} 断开连接")
    except Exception as e:
        print(f"[{datetime.now()}] 处理客户端 {addr} 时出错: {e}")
    finally:
        client_socket.close()
        print(f"[{datetime.now()}] 客户端 {addr} 连接已关闭")

def main():
    # 默认端口
    port = 8080
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            print("错误: 端口号必须是数字")
            sys.exit(1)
    
    # 创建服务器socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind(('0.0.0.0', port))
        server_socket.listen(5)
        print(f"LPR数据接收服务器启动在端口 {port}")
        print("等待连接...")
        
        while True:
            client_socket, addr = server_socket.accept()
            # 为每个客户端创建一个新线程
            client_thread = threading.Thread(
                target=handle_client, 
                args=(client_socket, addr)
            )
            client_thread.daemon = True
            client_thread.start()
            
    except KeyboardInterrupt:
        print("\n服务器正在关闭...")
    except Exception as e:
        print(f"服务器错误: {e}")
    finally:
        server_socket.close()

if __name__ == "__main__":
    main()
