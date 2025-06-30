CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -O2
LIBS = -lpcap
TARGET = lpr-parser
SOURCE = main.c

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE) $(LIBS)

clean:
	rm -f $(TARGET)

install-deps:
	@echo "安装依赖包 (Ubuntu/Debian):"
	sudo apt-get update
	sudo apt-get install -y libpcap-dev gcc make
	@echo "安装依赖包 (CentOS/RHEL):"
	@echo "sudo yum install libpcap-devel gcc make"
	@echo "或者:"
	@echo "sudo dnf install libpcap-devel gcc make"

.PHONY: clean install-deps
