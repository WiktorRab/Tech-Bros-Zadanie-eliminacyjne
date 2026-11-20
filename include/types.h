#ifndef TYPES_H
#define TYPES_H

#include <stdint.h>
#include <stddef.h>

#define TIMELINE_BUCKETS 40
#define SIZE_BUCKETS     7
#define MAX_HOSTS        8192
#define HOST_HT_SIZE     16384
#define MAX_PORTS        4096
#define PORT_HT_SIZE     8192
#define MAX_FLOWS        16384
#define FLOW_HT_SIZE     32768
#define MAX_ANOMALIES    128
#define MAX_FILES        32
#define MAX_TRACKED_PORTS 64

#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20

typedef enum {
    PROTO_OTHER = 0,
    PROTO_TCP   = 1,
    PROTO_UDP   = 2
} ProtoType;

typedef enum {
    SEV_LOW    = 0,
    SEV_MEDIUM = 1,
    SEV_HIGH   = 2
} Severity;

typedef struct {
    double   timestamp;
    uint32_t caplen;
    uint32_t wirelen;
    uint32_t src_ip;     /* host byte order */
    uint32_t dst_ip;     /* host byte order */
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  proto;
    uint8_t  tcp_flags;
    int      malformed;
} PacketInfo;

typedef struct {
    double   timestamp;
    uint32_t bytes;
    uint8_t  proto;
} PacketSample;

typedef struct {
    uint32_t ip;
    uint64_t pkts_sent;
    uint64_t pkts_recv;
    uint64_t bytes_sent;
    uint64_t bytes_recv;
    uint32_t syn_sent;
    uint32_t syn_ack_recv;
    uint32_t rst_count;
    uint32_t udp_sent;
    uint16_t distinct_ports[MAX_TRACKED_PORTS];
    uint32_t distinct_port_count;
} HostStat;

typedef struct {
    uint16_t port;
    uint8_t  proto;
    uint64_t packets;
    uint64_t bytes;
} PortStat;

typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  proto;
    uint64_t packets;
    uint64_t bytes;
    uint32_t syn_count;
    uint32_t rst_count;
    double   first_seen;
    double   last_seen;
} FlowStat;

typedef struct {
    uint64_t tcp_pkts;
    uint64_t udp_pkts;
    uint64_t other_pkts;
    uint64_t total_bytes;
} TimelineBucket;

typedef struct {
    uint64_t syn;
    uint64_t syn_ack;
    uint64_t ack;
    uint64_t fin;
    uint64_t rst;
    uint64_t psh;
    uint64_t urg;
    uint64_t null_scan;
    uint64_t xmas_scan;
    uint64_t syn_fin;
} TcpFlagStats;

typedef struct {
    Severity severity;
    char     category[48];
    char     title[96];
    char     details[192];
} Anomaly;

typedef struct {
    char     files[MAX_FILES][256];
    int      file_count;

    uint64_t total_packets;
    uint64_t total_bytes;
    uint64_t tcp_packets;
    uint64_t tcp_bytes;
    uint64_t udp_packets;
    uint64_t udp_bytes;
    uint64_t other_packets;
    uint64_t other_bytes;
    uint64_t malformed_packets;

    int      has_ts;
    double   first_ts;
    double   last_ts;
    double   duration;

    uint32_t min_pkt_size;
    uint32_t max_pkt_size;
    uint64_t size_buckets[SIZE_BUCKETS];

    TcpFlagStats   tcp_flags;
    TimelineBucket timeline[TIMELINE_BUCKETS];

    HostStat *hosts;
    int      *host_ht;
    size_t    host_count;

    PortStat *ports;
    int      *port_ht;
    size_t    port_count;

    FlowStat *flows;
    int      *flow_ht;
    size_t    flow_count;

    PacketSample *samples;
    size_t        sample_count;
    size_t        sample_cap;

    Anomaly anomalies[MAX_ANOMALIES];
    size_t  anomaly_count;
} AnalysisResult;

#endif /* TYPES_H */