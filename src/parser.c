#include "parser.h"
#include "analyzer.h"

#include <pcap.h>
#include <stdio.h>
#include <string.h>

static inline uint16_t read_be16(const uint8_t *p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}

static inline uint32_t read_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |
           ((uint32_t)p[3]);
}

typedef struct {
    AnalysisResult *res;
    int linktype;
} ParserContext;

static void packet_callback(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    ParserContext *ctx = (ParserContext *)user;
    PacketInfo pkt;
    memset(&pkt, 0, sizeof(pkt));

    pkt.timestamp = (double)h->ts.tv_sec + (double)h->ts.tv_usec / 1e6;
    pkt.caplen    = h->caplen;
    pkt.wirelen   = h->len;
    pkt.proto     = PROTO_OTHER;

    const uint8_t *data = (const uint8_t *)bytes;
    uint32_t len = h->caplen;
    uint32_t offset = 0;
    int is_ipv4 = 0;

    switch (ctx->linktype) {
        case DLT_EN10MB: {
            if (len < 14) {
                pkt.malformed = 1;
                analyzer_process_packet(ctx->res, &pkt);
                return;
            }
            uint16_t ethertype = read_be16(data + 12);
            offset = 14;
            /* Obsługa tagów VLAN 802.1Q / QinQ */
            while ((ethertype == 0x8100 || ethertype == 0x88A8) && len >= offset + 4) {
                ethertype = read_be16(data + offset + 2);
                offset += 4;
            }
            if (ethertype == 0x0800) {
                is_ipv4 = 1;
            }
            break;
        }
        case DLT_LINUX_SLL: {
            if (len < 16) {
                pkt.malformed = 1;
                analyzer_process_packet(ctx->res, &pkt);
                return;
            }
            if (read_be16(data + 14) == 0x0800) {
                is_ipv4 = 1;
                offset = 16;
            }
            break;
        }
#ifdef DLT_LINUX_SLL2
        case DLT_LINUX_SLL2: {
            if (len < 20) {
                pkt.malformed = 1;
                analyzer_process_packet(ctx->res, &pkt);
                return;
            }
            if (read_be16(data) == 0x0800) {
                is_ipv4 = 1;
                offset = 20;
            }
            break;
        }
#endif
        case DLT_RAW: {
            if (len >= 1 && (data[0] >> 4) == 4) {
                is_ipv4 = 1;
                offset = 0;
            }
            break;
        }
        case DLT_NULL: {
            if (len >= 4) {
                uint32_t family;
                memcpy(&family, data, sizeof(family));
                if (family == 2) { /* AF_INET */
                    is_ipv4 = 1;
                    offset = 4;
                }
            }
            break;
        }
        default:
            break;
    }

    if (!is_ipv4) {
        analyzer_process_packet(ctx->res, &pkt);
        return;
    }

    if (len < offset + 20) {
        pkt.malformed = 1;
        analyzer_process_packet(ctx->res, &pkt);
        return;
    }

    const uint8_t *ip = data + offset;
    uint8_t version = (uint8_t)(ip[0] >> 4);
    uint32_t ihl = (uint32_t)(ip[0] & 0x0F) * 4;

    if (version != 4 || ihl < 20 || offset + ihl > len) {
        pkt.malformed = 1;
        analyzer_process_packet(ctx->res, &pkt);
        return;
    }

    uint8_t ip_proto = ip[9];
    pkt.src_ip = read_be32(ip + 12);
    pkt.dst_ip = read_be32(ip + 16);

    const uint8_t *l4 = ip + ihl;
    uint32_t l4_len = len - (offset + ihl);

    if (ip_proto == 6) { /* TCP */
        pkt.proto = PROTO_TCP;
        if (l4_len < 20) {
            pkt.malformed = 1;
        } else {
            pkt.src_port  = read_be16(l4);
            pkt.dst_port  = read_be16(l4 + 2);
            uint32_t doff = (uint32_t)((l4[12] >> 4) & 0x0F) * 4;
            pkt.tcp_flags = l4[13];
            if (doff < 20 || doff > l4_len) {
                pkt.malformed = 1;
            }
        }
    } else if (ip_proto == 17) { /* UDP */
        pkt.proto = PROTO_UDP;
        if (l4_len < 8) {
            pkt.malformed = 1;
        } else {
            pkt.src_port = read_be16(l4);
            pkt.dst_port = read_be16(l4 + 2);
            uint16_t udp_len = read_be16(l4 + 4);
            if (udp_len < 8) {
                pkt.malformed = 1;
            }
        }
    }

    analyzer_process_packet(ctx->res, &pkt);
}

int parse_pcap_file(const char *filepath, AnalysisResult *res) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(filepath, errbuf);
    if (!handle) {
        fprintf(stderr, "[ERROR] Cannot open '%s': %s\n", filepath, errbuf);
        return -1;
    }

    if (res->file_count < MAX_FILES) {
        snprintf(res->files[res->file_count], sizeof(res->files[0]), "%s", filepath);
        res->file_count++;
    }

    ParserContext ctx;
    ctx.res = res;
    ctx.linktype = pcap_datalink(handle);

    int rc = pcap_loop(handle, 0, packet_callback, (u_char *)&ctx);
    pcap_close(handle);

    if (rc < 0) {
        fprintf(stderr, "[ERROR] Error while reading '%s'\n", filepath);
        return -1;
    }

    return 0;
}