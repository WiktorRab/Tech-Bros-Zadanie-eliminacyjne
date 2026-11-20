CC      := gcc
CFLAGS  := -std=c11 -D_DEFAULT_SOURCE -Wall -Wextra -O2 -Iinclude $(shell pkg-config --cflags cairo)
LDFLAGS := $(shell pkg-config --libs cairo) -lpcap -lm

SRCS    := src/main.c src/parser.c src/analyzer.c src/charts.c src/report.c
OBJS    := $(SRCS:.c=.o)
TARGET  := netscope
GEN_BIN := gen_sample_pcap

.PHONY: all clean test

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(GEN_BIN): tools/gen_sample_pcap.c
	$(CC) -std=c11 -Wall -Wextra -O2 $< -o $@

test: $(TARGET) $(GEN_BIN)
	./$(GEN_BIN)
	./$(TARGET) -o output samples/demo_traffic.pcap

clean:
	rm -f $(OBJS) $(TARGET) $(GEN_BIN)
	rm -rf output samples