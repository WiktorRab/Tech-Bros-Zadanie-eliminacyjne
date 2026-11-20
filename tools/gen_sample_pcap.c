#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static void put_be16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)(v & 0xFF); }
static void put_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)(v & 0xFF);
}

static uint32_t ipv4(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    return ((uint32_t)a << 24) | ((uint32_t)b << 16) | ((uint32_t)c << 8) | d;
}

static void write_pcap_header(FILE *f) {
    uint32_t magic = 0xa1b2c3d4U;
    uint16_t vmaj = 2, vmin = 4;
    int32_t  tz = 0;
    uint32_t sig = 0, snap = 65535, link = 1; /* Ethernet */
    fwrite(&magic, 4, 1, f);
    fwrite(&vmaj,  2, 1, f);
    fwrite(&vmin,  2, 1, f);
    fwrite(&tz,    4, 1, f);
    fwrite(&sig,   4, 1, f);
    fwrite(&snap,  4, 1, f);
    fwrite(&link,  4, 1, f);
}

static void write_packet(FILE *f, uint32_t sec, uint32_t usec,
                         uint32_t src_ip, uint32_t dst_ip,
                         uint16_t sport, uint16_t dport,
                         uint8_t proto, uint8_t tcp_flags, uint16_t payload_len) {
    uint8_t buf[2048];
    memset(buf, 0, sizeof(buf));

    /* Ethernet (14 B) */
    put_be16(buf + 12, 0x0800);

    uint16_t l4_hdr = (proto == 6) ? 20 : 8;
    uint16_t ip_tot = (uint16_t)(20 + l4_hdr + payload_len);
    uint32_t total_len = 14 + ip_tot;

    /* IPv4 (20 B) */
    uint8_t *ip = buf + 14;
    ip[0] = 0x45;
    put_be16(ip + 2, ip_tot);
    ip[8] = 64;
    ip[9] = proto;
    put_be32(ip + 12, src_ip);
    put_be32(ip + 16, dst_ip);

    /* L4 */
    uint8_t *l4 = ip + 20;
    put_be16(l4, sport);
    put_be16(l4 + 2, dport);
    if (proto == 6) {
        l4[12] = 0x50; /* data offset = 20 B */
        l4[13] = tcp_flags;
        put_be16(l4 + 14, 65535);
    } else {
        put_be16(l4 + 4, (uint16_t)(8 + payload_len));
    }

    uint32_t hdr[4] = { sec, usec, total_len, total_len };
    fwrite(hdr, 4, 4, f);
    fwrite(buf, 1, total_len, f);
}

int main(void) {
    mkdir("samples", 0755);
    FILE *f = fopen("samples/demo_traffic.pcap", "wb");
    if (!f) {
        perror("fopen");
        return 1;
    }
    write_pcap_header(f);

    uint32_t base_sec = 1730000000U;
    uint32_t client1 = ipv4(192, 168, 1, 10);
    uint32_t client2 = ipv4(192, 168, 1, 20);
    uint32_t scanner = ipv4(192, 168, 1, 55);
    uint32_t flooder = ipv4(192, 168, 1, 99);
    uint32_t srv_web = ipv4(10, 0, 0, 10);
    uint32_t srv_dns = ipv4(10, 0, 0, 53);

    /* 1. Normalny ruch HTTPS / HTTP / SSH / DNS przez 30 s */
    for (int i = 0; i < 240; i++) {
        uint32_t sec = base_sec + (uint32_t)(i / 8);
        uint32_t usec = (uint32_t)((i % 8) * 120000);
        write_packet(f, sec, usec, client1, srv_web, 50100, 443, 6, 0x18, (uint16_t)(200 + (i % 900)));
        write_packet(f, sec, usec + 15000, srv_web, client1, 443, 50100, 6, 0x10, (uint16_t)(600 + (i % 700)));
        if (i % 3 == 0) {
            write_packet(f, sec, usec + 30000, client2, srv_web, 51200, 80, 6, 0x18, 320);
        }
        if (i % 4 == 0) {
            write_packet(f, sec, usec + 45000, client2, srv_dns, 53000 + (uint16_t)i, 53, 17, 0, 48);
            write_packet(f, sec, usec + 60000, srv_dns, client2, 53, 53000 + (uint16_t)i, 17, 0, 110);
        }
    }

    /* 2. Skanowanie portów SYN + odpowiedzi RST */
    for (uint16_t p = 20; p < 60; p++) {
        uint32_t sec = base_sec + 10 + (p - 20) / 10;
        uint32_t usec = (uint32_t)(((p - 20) % 10) * 50000);
        write_packet(f, sec, usec, scanner, srv_web, 44000 + p, p, 6, 0x02, 0); /* SYN */
        write_packet(f, sec, usec + 5000, srv_web, scanner, p, 44000 + p, 6, 0x14, 0); /* RST+ACK */
    }

    /* 3. Sondy XMAS i NULL scan */
    write_packet(f, base_sec + 15, 10000, scanner, srv_web, 45001, 22, 6, 0x29, 0); /* FIN+PSH+URG */
    write_packet(f, base_sec + 15, 20000, scanner, srv_web, 45002, 80, 6, 0x00, 0); /* NULL */

    /* 4. Skok UDP (potential UDP flood) w okolicach 22. sekundy */
    for (int i = 0; i < 380; i++) {
        uint32_t sec = base_sec + 22;
        uint32_t usec = (uint32_t)(i * 2000);
        write_packet(f, sec, usec, flooder, srv_dns, (uint16_t)(40000 + i), 53, 17, 0, 64);
    }

    fclose(f);
    printf("[OK] Generated samples/demo_traffic.pcap\n");
    return 0;
}