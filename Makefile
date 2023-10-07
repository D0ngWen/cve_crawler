TARGET := cve_crawler.exe

all: $(TARGET)

$(TARGET): main.go
	go build -o $@ $^
