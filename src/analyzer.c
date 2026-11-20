#include "analyzer.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static inline uint32_t hash_u32(uint32_t x) {
    x ^= x >> 16;
    x *= 0x7feb352dU;
    x ^= x >> 15;
    x *= 0x846ca68bU;
    x ^= x >> 16;
    return x;
}

static HostStat *get_or_create_host(AnalysisResult *res, uint32_t ip) {
    uint32_t mask = HOST_HT_SIZE - 1;
    uint32_t slot = hash_u32(ip) & mask;

    for (uint32_t probe = 0; probe < HOST_HT_SIZE; probe++) {
        int idx = res->host_ht[slot];
        if (idx == -1) {
            if (res->host_count >= MAX_HOSTS) {
                return NULL;
            }
            int new_idx = (int)res->host_count++;
            HostStat *h = &res->hosts[new_idx];
            memset(h, 0, sizeof(*h));
            h->ip = ip;
            res->host_ht[slot] = new_idx;
            return h;
        }
        if (res->hosts[idx].ip == ip) {
            return &res->hosts[idx];
        }
        slot = (slot + 1) & mask;
    }
    return NULL;
}

static void host_record_dst_port(HostStat *h, uint16_t port) {
    for (uint32_t i = 0; i < h->distinct_port_count; i++) {
        if (h->distinct_ports[i] == port) {
            return;
        }
    }
    if (h->distinct_port_count < MAX_TRACKED_PORTS) {
        h->distinct_ports[h->distinct_port_count++] = port;
    }
}

static PortStat *get_or_create_port(AnalysisResult *res, uint16_t port, uint8_t proto) {
    uint32_t key = ((uint32_t)port << 8) | proto;
    uint32_t mask = PORT_HT_SIZE - 1;
    uint32_t slot = hash_u32(key) & mask;

    for (uint32_t probe = 0; probe < PORT_HT_SIZE; probe++) {
        int idx = res->port_ht[slot];
        if (idx == -1) {
            if (res->port_count >= MAX_PORTS) {
                return NULL;
            }
            int new_idx = (int)res->port_count++;
            PortStat *p = &res->ports[new_idx];
            memset(p, 0, sizeof(*p));
            p->port = port;
            p->proto = proto;
            res->port_ht[slot] = new_idx;
            return p;
        }
        if (res->ports[idx].port == port && res->ports[idx].proto == proto) {
            return &res->ports[idx];
        }
        slot = (slot + 1) & mask;
    }
    return NULL;
}

static FlowStat *get_or_create_flow(AnalysisResult *res, const PacketInfo *pkt) {
    uint32_t h = hash_u32(pkt->src_ip ^ (pkt->dst_ip * 2654435761U));
    h ^= hash_u32(((uint32_t)pkt->src_port << 16) | pkt->dst_port);
    h ^= (uint32_t)pkt->proto * 0x9e3779b1U;

    uint32_t mask = FLOW_HT_SIZE - 1;
    uint32_t slot = h & mask;

    for (uint32_t probe = 0; probe < FLOW_HT_SIZE; probe++) {
        int idx = res->flow_ht[slot];
        if (idx == -1) {
            if (res->flow_count >= MAX_FLOWS) {
                return NULL;
            }
            int new_idx = (int)res->flow_count++;
            FlowStat *f = &res->flows[new_idx];
            memset(f, 0, sizeof(*f));
            f->src_ip     = pkt->src_ip;
            f->dst_ip     = pkt->dst_ip;
            f->src_port   = pkt->src_port;
            f->dst_port   = pkt->dst_port;
            f->proto      = pkt->proto;
            f->first_seen = pkt->timestamp;
            f->last_seen  = pkt->timestamp;
            res->flow_ht[slot] = new_idx;
            return f;
        }
        FlowStat *f = &res->flows[idx];
        if (f->src_ip == pkt->src_ip && f->dst_ip == pkt->dst_ip &&
            f->src_port == pkt->src_port && f->dst_port == pkt->dst_port &&
            f->proto == pkt->proto) {
            return f;
        }
        slot = (slot + 1) & mask;
    }
    return NULL;
}

static void add_anomaly(AnalysisResult *res, Severity sev, const char *cat,
                        const char *title, const char *details) {
    if (res->anomaly_count >= MAX_ANOMALIES) {
        return;
    }
    Anomaly *a = &res->anomalies[res->anomaly_count++];
    a->severity = sev;
    snprintf(a->category, sizeof(a->category), "%s", cat);
    snprintf(a->title, sizeof(a->title), "%s", title);
    snprintf(a->details, sizeof(a->details), "%s", details);
}

int analyzer_init(AnalysisResult *res) {
    memset(res, 0, sizeof(*res));
    res->min_pkt_size = UINT32_MAX;

    res->hosts   = calloc(MAX_HOSTS, sizeof(HostStat));
    res->host_ht = malloc(HOST_HT_SIZE * sizeof(int));
    res->ports   = calloc(MAX_PORTS, sizeof(PortStat));
    res->port_ht = malloc(PORT_HT_SIZE * sizeof(int));
    res->flows   = calloc(MAX_FLOWS, sizeof(FlowStat));
    res->flow_ht = malloc(FLOW_HT_SIZE * sizeof(int));

    res->sample_cap = 4096;
    res->samples = malloc(res->sample_cap * sizeof(PacketSample));

    if (!res->hosts || !res->host_ht || !res->ports || !res->port_ht ||
        !res->flows || !res->flow_ht || !res->samples) {
        analyzer_free(res);
        return -1;
    }

    for (int i = 0; i < HOST_HT_SIZE; i++) res->host_ht[i] = -1;
    for (int i = 0; i < PORT_HT_SIZE; i++) res->port_ht[i] = -1;
    for (int i = 0; i < FLOW_HT_SIZE; i++) res->flow_ht[i] = -1;

    return 0;
}

void analyzer_free(AnalysisResult *res) {
    free(res->hosts);
    free(res->host_ht);
    free(res->ports);
    free(res->port_ht);
    free(res->flows);
    free(res->flow_ht);
    free(res->samples);
    res->hosts = NULL;
    res->host_ht = NULL;
    res->ports = NULL;
    res->port_ht = NULL;
    res->flows = NULL;
    res->flow_ht = NULL;
    res->samples = NULL;
}

static size_t size_bucket_index(uint32_t wirelen) {
    if (wirelen < 64)    return 0;
    if (wirelen < 128)   return 1;
    if (wirelen < 256)   return 2;
    if (wirelen < 512)   return 3;
    if (wirelen < 1024)  return 4;
    if (wirelen <= 1500) return 5;
    return 6;
}

void analyzer_process_packet(AnalysisResult *res, const PacketInfo *pkt) {
    res->total_packets++;
    res->total_bytes += pkt->wirelen;

    if (!res->has_ts) {
        res->first_ts = pkt->timestamp;
        res->last_ts  = pkt->timestamp;
        res->has_ts   = 1;
    } else {
        if (pkt->timestamp < res->first_ts) res->first_ts = pkt->timestamp;
        if (pkt->timestamp > res->last_ts)  res->last_ts  = pkt->timestamp;
    }

    if (pkt->wirelen < res->min_pkt_size) res->min_pkt_size = pkt->wirelen;
    if (pkt->wirelen > res->max_pkt_size) res->max_pkt_size = pkt->wirelen;
    res->size_buckets[size_bucket_index(pkt->wirelen)]++;

    if (pkt->malformed) {
        res->malformed_packets++;
    }

    /* Zapis próbki do osi czasu */
    if (res->sample_count == res->sample_cap) {
        size_t new_cap = res->sample_cap * 2;
        PacketSample *tmp = realloc(res->samples, new_cap * sizeof(PacketSample));
        if (tmp) {
            res->samples = tmp;
            res->sample_cap = new_cap;
        }
    }
    if (res->sample_count < res->sample_cap) {
        res->samples[res->sample_count].timestamp = pkt->timestamp;
        res->samples[res->sample_count].bytes     = pkt->wirelen;
        res->samples[res->sample_count].proto     = pkt->proto;
        res->sample_count++;
    }

    if (pkt->proto == PROTO_TCP) {
        res->tcp_packets++;
        res->tcp_bytes += pkt->wirelen;
    } else if (pkt->proto == PROTO_UDP) {
        res->udp_packets++;
        res->udp_bytes += pkt->wirelen;
    } else {
        res->other_packets++;
        res->other_bytes += pkt->wirelen;
        return;
    }

    if (pkt->malformed) {
        return;
    }

    /* Statystyki hostów */
    HostStat *src = get_or_create_host(res, pkt->src_ip);
    HostStat *dst = get_or_create_host(res, pkt->dst_ip);

    if (src) {
        src->pkts_sent++;
        src->bytes_sent += pkt->wirelen;
        if (pkt->proto == PROTO_UDP) {
            src->udp_sent++;
        }
    }
    if (dst) {
        dst->pkts_recv++;
        dst->bytes_recv += pkt->wirelen;
    }

    /* Flagi TCP */
    if (pkt->proto == PROTO_TCP) {
        uint8_t f = pkt->tcp_flags;
        if ((f & TCP_SYN) && !(f & TCP_ACK)) {
            res->tcp_flags.syn++;
            if (src) {
                src->syn_sent++;
                host_record_dst_port(src, pkt->dst_port);
            }
        }
        if ((f & TCP_SYN) && (f & TCP_ACK)) {
            res->tcp_flags.syn_ack++;
            if (dst) {
                dst->syn_ack_recv++;
            }
        }
        if (f & TCP_ACK) res->tcp_flags.ack++;
        if (f & TCP_FIN) res->tcp_flags.fin++;
        if (f & TCP_RST) {
            res->tcp_flags.rst++;
            if (src) src->rst_count++;
        }
        if (f & TCP_PSH) res->tcp_flags.psh++;
        if (f & TCP_URG) res->tcp_flags.urg++;

        /* Podejrzane kombinacje flag */
        if (f == 0) {
            res->tcp_flags.null_scan++;
        }
        if ((f & (TCP_FIN | TCP_PSH | TCP_URG)) == (TCP_FIN | TCP_PSH | TCP_URG)) {
            res->tcp_flags.xmas_scan++;
        }
        if ((f & (TCP_SYN | TCP_FIN)) == (TCP_SYN | TCP_FIN)) {
            res->tcp_flags.syn_fin++;
        }
    }

    /* Statystyki portów docelowych (lub niższy port usługowy) */
    uint16_t service_port = (pkt->dst_port <= pkt->src_port || pkt->dst_port < 1024)
                            ? pkt->dst_port : pkt->src_port;
    PortStat *ps = get_or_create_port(res, service_port, pkt->proto);
    if (ps) {
        ps->packets++;
        ps->bytes += pkt->wirelen;
    }

    /* Śledzenie przepływów (5-tuple) */
    FlowStat *fl = get_or_create_flow(res, pkt);
    if (fl) {
        fl->packets++;
        fl->bytes += pkt->wirelen;
        if (pkt->timestamp < fl->first_seen) fl->first_seen = pkt->timestamp;
        if (pkt->timestamp > fl->last_seen)  fl->last_seen  = pkt->timestamp;
        if (pkt->proto == PROTO_TCP) {
            if ((pkt->tcp_flags & TCP_SYN) && !(pkt->tcp_flags & TCP_ACK)) fl->syn_count++;
            if (pkt->tcp_flags & TCP_RST) fl->rst_count++;
        }
    }
}

static int cmp_hosts_desc(const void *a, const void *b) {
    const HostStat *ha = (const HostStat *)a;
    const HostStat *hb = (const HostStat *)b;
    uint64_t va = ha->bytes_sent + ha->bytes_recv;
    uint64_t vb = hb->bytes_sent + hb->bytes_recv;
    if (vb > va) return 1;
    if (vb < va) return -1;
    return 0;
}

static int cmp_ports_desc(const void *a, const void *b) {
    const PortStat *pa = (const PortStat *)a;
    const PortStat *pb = (const PortStat *)b;
    if (pb->packets > pa->packets) return 1;
    if (pb->packets < pa->packets) return -1;
    return 0;
}

static int cmp_flows_desc(const void *a, const void *b) {
    const FlowStat *fa = (const FlowStat *)a;
    const FlowStat *fb = (const FlowStat *)b;
    if (fb->bytes > fa->bytes) return 1;
    if (fb->bytes < fa->bytes) return -1;
    return 0;
}

static int cmp_anomalies_sev(const void *a, const void *b) {
    const Anomaly *aa = (const Anomaly *)a;
    const Anomaly *ab = (const Anomaly *)b;
    return (int)ab->severity - (int)aa->severity;
}

static void detect_anomalies(AnalysisResult *res) {
    char ipbuf[32];
    char details[192];

    /* 1. Skanowanie portów (SYN Scan) & SYN Flood per host */
    for (size_t i = 0; i < res->host_count; i++) {
        const HostStat *h = &res->hosts[i];
        format_ip(h->ip, ipbuf, sizeof(ipbuf));

        if (h->distinct_port_count >= 15 && h->syn_sent >= 15 &&
            h->syn_ack_recv * 3 < h->syn_sent) {
            snprintf(details, sizeof(details),
                     "Host %s probed %u+ distinct TCP ports (%u SYN sent, %u SYN-ACK recv).",
                     ipbuf, h->distinct_port_count, h->syn_sent, h->syn_ack_recv);
            add_anomaly(res, SEV_HIGH, "Port Scanning",
                        "Potential TCP SYN Port Scan Detected", details);
        } else if (h->syn_sent >= 50 && h->syn_ack_recv * 5 < h->syn_sent) {
            snprintf(details, sizeof(details),
                     "Host %s sent %u SYN packets with only %u SYN-ACK responses (<20%%).",
                     ipbuf, h->syn_sent, h->syn_ack_recv);
            add_anomaly(res, SEV_HIGH, "DoS / Flooding",
                        "Half-Open Connection Exhaustion (SYN Flood)", details);
        }

        /* 2. UDP Flood per host */
        if (h->udp_sent >= 150 && res->total_packets > 0 &&
            (double)h->udp_sent / (double)res->total_packets > 0.30) {
            double pct = 100.0 * (double)h->udp_sent / (double)res->total_packets;
            snprintf(details, sizeof(details),
                     "Host %s generated %u UDP packets (%.1f%% of total traffic).",
                     ipbuf, h->udp_sent, pct);
            add_anomaly(res, SEV_HIGH, "UDP Anomaly",
                        "High-Volume UDP Traffic Burst / Potential Flood", details);
        }
    }

    /* 3. Podejrzane kombinacje flag TCP (NULL / XMAS / SYN+FIN) */
    if (res->tcp_flags.null_scan > 0) {
        snprintf(details, sizeof(details),
                 "Observed %llu TCP packets with all control flags set to zero.",
                 (unsigned long long)res->tcp_flags.null_scan);
        add_anomaly(res, SEV_HIGH, "Stealth Scan",
                    "TCP NULL Scan Packets Detected", details);
    }
    if (res->tcp_flags.xmas_scan > 0) {
        snprintf(details, sizeof(details),
                 "Observed %llu TCP packets with FIN+PSH+URG flags simultaneously set.",
                 (unsigned long long)res->tcp_flags.xmas_scan);
        add_anomaly(res, SEV_HIGH, "Stealth Scan",
                    "TCP XMAS Scan Packets Detected", details);
    }
    if (res->tcp_flags.syn_fin > 0) {
        snprintf(details, sizeof(details),
                 "Observed %llu illegal TCP packets with both SYN and FIN flags set.",
                 (unsigned long long)res->tcp_flags.syn_fin);
        add_anomaly(res, SEV_HIGH, "Protocol Violation",
                    "Illegal TCP SYN+FIN Flag Combination", details);
    }

    /* 4. Wysoki współczynnik pakietów RST */
    if (res->tcp_packets >= 20 && res->tcp_flags.rst >= 10) {
        double rst_ratio = (double)res->tcp_flags.rst / (double)res->tcp_packets;
        if (rst_ratio > 0.10) {
            Severity sev = (rst_ratio > 0.25) ? SEV_HIGH : SEV_MEDIUM;
            snprintf(details, sizeof(details),
                     "TCP RST packets account for %.1f%% (%llu/%llu) of TCP traffic (rejected/reset connections).",
                     rst_ratio * 100.0,
                     (unsigned long long)res->tcp_flags.rst,
                     (unsigned long long)res->tcp_packets);
            add_anomaly(res, sev, "Connection Health",
                        "Elevated TCP Reset (RST) Ratio", details);
        }
    }

    /* 5. Nagłe skoki natężenia ruchu (z-score > 3.0) */
    double mean = 0.0;
    for (int i = 0; i < TIMELINE_BUCKETS; i++) {
        mean += (double)(res->timeline[i].tcp_pkts + res->timeline[i].udp_pkts + res->timeline[i].other_pkts);
    }
    mean /= (double)TIMELINE_BUCKETS;

    double var = 0.0;
    for (int i = 0; i < TIMELINE_BUCKETS; i++) {
        double v = (double)(res->timeline[i].tcp_pkts + res->timeline[i].udp_pkts + res->timeline[i].other_pkts);
        double d = v - mean;
        var += d * d;
    }
    double stddev = sqrt(var / (double)TIMELINE_BUCKETS);

    if (stddev > 1.0) {
        int peak_idx = -1;
        uint64_t peak_val = 0;
        for (int i = 0; i < TIMELINE_BUCKETS; i++) {
            uint64_t v = res->timeline[i].tcp_pkts + res->timeline[i].udp_pkts + res->timeline[i].other_pkts;
            if ((double)v > mean + 3.0 * stddev && v >= 25 && v > peak_val) {
                peak_val = v;
                peak_idx = i;
            }
        }
        if (peak_idx >= 0) {
            double t_off = (res->duration * (double)peak_idx) / (double)TIMELINE_BUCKETS;
            snprintf(details, sizeof(details),
                     "Traffic spike at +%.1fs: %llu pkts/interval (mean %.1f, >3 sigma deviation).",
                     t_off, (unsigned long long)peak_val, mean);
            add_anomaly(res, SEV_MEDIUM, "Traffic Burst",
                        "Statistical Traffic Volume Spike Detected", details);
        }
    }

    /* 6. Uszkodzone / obcięte pakiety */
    if (res->malformed_packets > 0) {
        double pct = res->total_packets > 0
                     ? 100.0 * (double)res->malformed_packets / (double)res->total_packets
                     : 0.0;
        Severity sev = (pct > 5.0) ? SEV_MEDIUM : SEV_LOW;
        snprintf(details, sizeof(details),
                 "Found %llu malformed or truncated packets (%.2f%% of capture).",
                 (unsigned long long)res->malformed_packets, pct);
        add_anomaly(res, sev, "Packet Integrity",
                    "Malformed or Truncated Headers Detected", details);
    }

    if (res->anomaly_count > 1) {
        qsort(res->anomalies, res->anomaly_count, sizeof(Anomaly), cmp_anomalies_sev);
    }
}

void analyzer_finalize(AnalysisResult *res) {
    if (res->total_packets == 0) {
        res->min_pkt_size = 0;
        return;
    }

    res->duration = res->last_ts - res->first_ts;
    if (res->duration < 0.0) {
        res->duration = 0.0;
    }

    /* Wypełnienie przedziałów osi czasu */
    for (size_t i = 0; i < res->sample_count; i++) {
        int b = 0;
        if (res->duration > 1e-9) {
            double frac = (res->samples[i].timestamp - res->first_ts) / res->duration;
            b = (int)(frac * (double)TIMELINE_BUCKETS);
            if (b < 0) b = 0;
            if (b >= TIMELINE_BUCKETS) b = TIMELINE_BUCKETS - 1;
        }
        res->timeline[b].total_bytes += res->samples[i].bytes;
        if (res->samples[i].proto == PROTO_TCP)      res->timeline[b].tcp_pkts++;
        else if (res->samples[i].proto == PROTO_UDP) res->timeline[b].udp_pkts++;
        else                                         res->timeline[b].other_pkts++;
    }

    if (res->host_count > 1) qsort(res->hosts, res->host_count, sizeof(HostStat), cmp_hosts_desc);
    if (res->port_count > 1) qsort(res->ports, res->port_count, sizeof(PortStat), cmp_ports_desc);
    if (res->flow_count > 1) qsort(res->flows, res->flow_count, sizeof(FlowStat), cmp_flows_desc);

    detect_anomalies(res);
}

void format_ip(uint32_t ip, char *buf, size_t len) {
    snprintf(buf, len, "%u.%u.%u.%u",
             (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
             (ip >> 8) & 0xFF, ip & 0xFF);
}

void format_bytes(uint64_t bytes, char *buf, size_t len) {
    if (bytes >= 1024ULL * 1024ULL * 1024ULL) {
        snprintf(buf, len, "%.2f GB", (double)bytes / (1024.0 * 1024.0 * 1024.0));
    } else if (bytes >= 1024ULL * 1024ULL) {
        snprintf(buf, len, "%.2f MB", (double)bytes / (1024.0 * 1024.0));
    } else if (bytes >= 1024ULL) {
        snprintf(buf, len, "%.1f KB", (double)bytes / 1024.0);
    } else {
        snprintf(buf, len, "%llu B", (unsigned long long)bytes);
    }
}

const char *port_service_name(uint16_t port) {
    switch (port) {
        case 20:   return "FTP-Data";
        case 21:   return "FTP";
        case 22:   return "SSH";
        case 23:   return "Telnet";
        case 25:   return "SMTP";
        case 53:   return "DNS";
        case 67:
        case 68:   return "DHCP";
        case 80:   return "HTTP";
        case 110:  return "POP3";
        case 123:  return "NTP";
        case 143:  return "IMAP";
        case 161:  return "SNMP";
        case 443:  return "HTTPS";
        case 445:  return "SMB";
        case 587:  return "SMTP-TLS";
        case 993:  return "IMAPS";
        case 1433: return "MSSQL";
        case 1900: return "SSDP";
        case 3306: return "MySQL";
        case 3389: return "RDP";
        case 5353: return "mDNS";
        case 5432: return "PostgreSQL";
        case 6379: return "Redis";
        case 8080: return "HTTP-Alt";
        case 8443: return "HTTPS-Alt";
        default:   return "Other";
    }
}