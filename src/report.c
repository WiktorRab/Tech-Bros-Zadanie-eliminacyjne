#include "report.h"
#include "analyzer.h"
#include "charts.h"

#include <cairo.h>
#include <cairo-pdf.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define PAGE_W 595.0
#define PAGE_H 842.0
#define MARGIN 36.0

static void draw_header(cairo_t *cr, const char *subtitle, int page_num, int total_pages) {
    cairo_set_source_rgb(cr, 0.09, 0.14, 0.24);
    cairo_rectangle(cr, 0, 0, PAGE_W, 64.0);
    cairo_fill(cr);

    cairo_select_font_face(cr, "DejaVu Sans", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_BOLD);
    cairo_set_font_size(cr, 16.0);
    cairo_set_source_rgb(cr, 1.0, 1.0, 1.0);
    cairo_move_to(cr, MARGIN, 30.0);
    cairo_show_text(cr, "NETSCOPE // TCP & UDP Network Traffic Report");

    cairo_select_font_face(cr, "DejaVu Sans", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
    cairo_set_font_size(cr, 9.5);
    cairo_set_source_rgb(cr, 0.72, 0.80, 0.90);
    cairo_move_to(cr, MARGIN, 48.0);
    cairo_show_text(cr, subtitle);

    /* Stopka */
    cairo_set_source_rgb(cr, 0.85, 0.88, 0.92);
    cairo_set_line_width(cr, 0.8);
    cairo_move_to(cr, MARGIN, PAGE_H - 32.0);
    cairo_line_to(cr, PAGE_W - MARGIN, PAGE_H - 32.0);
    cairo_stroke(cr);

    time_t now = time(NULL);
    struct tm *tm_now = localtime(&now);
    char tbuf[64];
    strftime(tbuf, sizeof(tbuf), "Generated: %Y-%m-%d %H:%M:%S", tm_now);

    cairo_set_font_size(cr, 8.0);
    cairo_set_source_rgb(cr, 0.45, 0.50, 0.58);
    cairo_move_to(cr, MARGIN, PAGE_H - 18.0);
    cairo_show_text(cr, tbuf);

    char pbuf[32];
    snprintf(pbuf, sizeof(pbuf), "Page %d of %d", page_num, total_pages);
    cairo_move_to(cr, PAGE_W - MARGIN - 55.0, PAGE_H - 18.0);
    cairo_show_text(cr, pbuf);
}

static void draw_section_title(cairo_t *cr, double y, const char *title) {
    cairo_select_font_face(cr, "DejaVu Sans", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_BOLD);
    cairo_set_font_size(cr, 12.0);
    cairo_set_source_rgb(cr, 0.12, 0.16, 0.23);
    cairo_move_to(cr, MARGIN, y);
    cairo_show_text(cr, title);

    cairo_set_source_rgb(cr, 0.15, 0.39, 0.92);
    cairo_set_line_width(cr, 1.5);
    cairo_move_to(cr, MARGIN, y + 4.0);
    cairo_line_to(cr, MARGIN + 50.0, y + 4.0);
    cairo_stroke(cr);
}

static void draw_kpi_card(cairo_t *cr, double x, double y, double w, double h,
                          const char *label, const char *value, const char *sub,
                          double r, double g, double b) {
    cairo_set_source_rgb(cr, 0.97, 0.98, 1.0);
    cairo_rectangle(cr, x, y, w, h);
    cairo_fill(cr);

    cairo_set_source_rgb(cr, r, g, b);
    cairo_rectangle(cr, x, y, 4.0, h);
    cairo_fill(cr);

    cairo_set_source_rgb(cr, 0.85, 0.88, 0.92);
    cairo_set_line_width(cr, 0.8);
    cairo_rectangle(cr, x, y, w, h);
    cairo_stroke(cr);

    cairo_select_font_face(cr, "DejaVu Sans", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_BOLD);
    cairo_set_font_size(cr, 8.0);
    cairo_set_source_rgb(cr, 0.45, 0.50, 0.58);
    cairo_move_to(cr, x + 12.0, y + 16.0);
    cairo_show_text(cr, label);

    cairo_set_font_size(cr, 15.0);
    cairo_set_source_rgb(cr, 0.09, 0.14, 0.24);
    cairo_move_to(cr, x + 12.0, y + 36.0);
    cairo_show_text(cr, value);

    cairo_select_font_face(cr, "DejaVu Sans", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
    cairo_set_font_size(cr, 7.8);
    cairo_set_source_rgb(cr, 0.45, 0.50, 0.58);
    cairo_move_to(cr, x + 12.0, y + 50.0);
    cairo_show_text(cr, sub);
}

static void render_page_summary(cairo_t *cr, const AnalysisResult *res) {
    char sub[256];
    snprintf(sub, sizeof(sub), "Executive Summary  |  Input files: %d  |  Capture duration: %.2f s",
             res->file_count, res->duration);
    draw_header(cr, sub, 1, 3);

    /* Karty KPI */
    double cw = (PAGE_W - 2 * MARGIN - 3 * 10.0) / 4.0;
    double ky = 82.0;

    char v1[32], s1[48], v2[32], s2[48], v3[32], s3[48], v4[32], s4[48];
    double eff_dur = res->duration > 1e-6 ? res->duration : 1.0;
    double pps = (double)res->total_packets / eff_dur;
    double kbps = ((double)res->total_bytes * 8.0 / 1000.0) / eff_dur;

    snprintf(v1, sizeof(v1), "%llu", (unsigned long long)res->total_packets);
    snprintf(s1, sizeof(s1), "%.1f pkt/s avg", pps);

    format_bytes(res->total_bytes, v2, sizeof(v2));
    snprintf(s2, sizeof(s2), "%.1f kbps avg", kbps);

    snprintf(v3, sizeof(v3), "%zu", res->host_count);
    snprintf(s3, sizeof(s3), "%zu active flows", res->flow_count);

    snprintf(v4, sizeof(v4), "%zu", res->anomaly_count);
    snprintf(s4, sizeof(s4), res->anomaly_count > 0 ? "Action recommended" : "Traffic normal");

    draw_kpi_card(cr, MARGIN,                ky, cw, 60.0, "TOTAL PACKETS", v1, s1, 0.15, 0.39, 0.92);
    draw_kpi_card(cr, MARGIN + (cw + 10),    ky, cw, 60.0, "TOTAL VOLUME",  v2, s2, 0.05, 0.58, 0.53);
    draw_kpi_card(cr, MARGIN + 2*(cw + 10),  ky, cw, 60.0, "UNIQUE HOSTS",  v3, s3, 0.39, 0.40, 0.95);
    draw_kpi_card(cr, MARGIN + 3*(cw + 10),  ky, cw, 60.0, "ANOMALIES",     v4, s4,
                  res->anomaly_count > 0 ? 0.86 : 0.08,
                  res->anomaly_count > 0 ? 0.15 : 0.64,
                  res->anomaly_count > 0 ? 0.15 : 0.29);

    /* Sekcja 1: Podsumowanie protokołów */
    double y = 168.0;
    draw_section_title(cr, y, "1. Traffic Breakdown & Packet Metrics");
    y += 18.0;

    /* Nagłówek tabeli */
    cairo_set_source_rgb(cr, 0.93, 0.95, 0.98);
    cairo_rectangle(cr, MARGIN, y, PAGE_W - 2 * MARGIN, 20.0);
    cairo_fill(cr);

    cairo_select_font_face(cr, "DejaVu Sans", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_BOLD);
    cairo_set_font_size(cr, 8.5);
    cairo_set_source_rgb(cr, 0.20, 0.25, 0.33);
    cairo_move_to(cr, MARGIN + 8,   y + 13); cairo_show_text(cr, "Protocol");
    cairo_move_to(cr, MARGIN + 130, y + 13); cairo_show_text(cr, "Packets");
    cairo_move_to(cr, MARGIN + 225, y + 13); cairo_show_text(cr, "Packet Share");
    cairo_move_to(cr, MARGIN + 330, y + 13); cairo_show_text(cr, "Volume");
    cairo_move_to(cr, MARGIN + 430, y + 13); cairo_show_text(cr, "Volume Share");
    y += 20.0;

    struct { const char *name; uint64_t pkts; uint64_t bytes; } rows[3] = {
        { "TCP",           res->tcp_packets,   res->tcp_bytes },
        { "UDP",           res->udp_packets,   res->udp_bytes },
        { "Other / L2-L3", res->other_packets, res->other_bytes }
    };

    cairo_select_font_face(cr, "DejaVu Sans", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
    for (int i = 0; i < 3; i++) {
        double ppct = res->total_packets ? 100.0 * (double)rows[i].pkts / (double)res->total_packets : 0.0;
        double bpct = res->total_bytes   ? 100.0 * (double)rows[i].bytes / (double)res->total_bytes : 0.0;
        char bbuf[32], tbuf[32];
        format_bytes(rows[i].bytes, bbuf, sizeof(bbuf));

        cairo_set_source_rgb(cr, 0.15, 0.20, 0.28);
        cairo_move_to(cr, MARGIN + 8,   y + 13); cairo_show_text(cr, rows[i].name);
        snprintf(tbuf, sizeof(tbuf), "%llu", (unsigned long long)rows[i].pkts);
        cairo_move_to(cr, MARGIN + 130, y + 13); cairo_show_text(cr, tbuf);
        snprintf(tbuf, sizeof(tbuf), "%.1f%%", ppct);
        cairo_move_to(cr, MARGIN + 225, y + 13); cairo_show_text(cr, tbuf);
        cairo_move_to(cr, MARGIN + 330, y + 13); cairo_show_text(cr, bbuf);
        snprintf(tbuf, sizeof(tbuf), "%.1f%%", bpct);
        cairo_move_to(cr, MARGIN + 430, y + 13); cairo_show_text(cr, tbuf);

        cairo_set_source_rgb(cr, 0.90, 0.92, 0.95);
        cairo_set_line_width(cr, 0.6);
        cairo_move_to(cr, MARGIN, y + 18);
        cairo_line_to(cr, PAGE_W - MARGIN, y + 18);
        cairo_stroke(cr);
        y += 18.0;
    }

    double avg_sz = res->total_packets ? (double)res->total_bytes / (double)res->total_packets : 0.0;
    char szline[160];
    snprintf(szline, sizeof(szline),
             "Packet size stats: Min = %u B   |   Avg = %.1f B   |   Max = %u B   |   Malformed = %llu",
             res->min_pkt_size, avg_sz, res->max_pkt_size, (unsigned long long)res->malformed_packets);
    cairo_set_font_size(cr, 8.5);
    cairo_set_source_rgb(cr, 0.35, 0.40, 0.48);
    cairo_move_to(cr, MARGIN, y + 16);
    cairo_show_text(cr, szline);

    /* Sekcja 2: Top Talkers */
    y += 46.0;
    draw_section_title(cr, y, "2. Top Communicating Hosts (Top Talkers)");
    y += 18.0;

    cairo_set_source_rgb(cr, 0.93, 0.95, 0.98);
    cairo_rectangle(cr, MARGIN, y, PAGE_W - 2 * MARGIN, 20.0);
    cairo_fill(cr);

    cairo_select_font_face(cr, "DejaVu Sans", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_BOLD);
    cairo_set_font_size(cr, 8.2);
    cairo_set_source_rgb(cr, 0.20, 0.25, 0.33);
    cairo_move_to(cr, MARGIN + 8,   y + 13); cairo_show_text(cr, "IP Address");
    cairo_move_to(cr, MARGIN + 125, y + 13); cairo_show_text(cr, "Sent Pkts");
    cairo_move_to(cr, MARGIN + 195, y + 13); cairo_show_text(cr, "Recv Pkts");
    cairo_move_to(cr, MARGIN + 265, y + 13); cairo_show_text(cr, "Sent Vol");
    cairo_move_to(cr, MARGIN + 340, y + 13); cairo_show_text(cr, "Recv Vol");
    cairo_move_to(cr, MARGIN + 415, y + 13); cairo_show_text(cr, "SYN / RST");
    y += 20.0;

    size_t max_h = res->host_count < 14 ? res->host_count : 14;
    cairo_select_font_face(cr, "DejaVu Sans", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);

    for (size_t i = 0; i < max_h; i++) {
        const HostStat *h = &res->hosts[i];
        char ip[32], sb[32], rb[32], tmp[32];
        format_ip(h->ip, ip, sizeof(ip));
        format_bytes(h->bytes_sent, sb, sizeof(sb));
        format_bytes(h->bytes_recv, rb, sizeof(rb));

        if (i % 2 == 1) {
            cairo_set_source_rgb(cr, 0.98, 0.985, 0.995);
            cairo_rectangle(cr, MARGIN, y, PAGE_W - 2 * MARGIN, 18.0);
            cairo_fill(cr);
        }

        cairo_set_source_rgb(cr, 0.15, 0.20, 0.28);
        cairo_move_to(cr, MARGIN + 8,   y + 12); cairo_show_text(cr, ip);
        snprintf(tmp, sizeof(tmp), "%llu", (unsigned long long)h->pkts_sent);
        cairo_move_to(cr, MARGIN + 125, y + 12); cairo_show_text(cr, tmp);
        snprintf(tmp, sizeof(tmp), "%llu", (unsigned long long)h->pkts_recv);
        cairo_move_to(cr, MARGIN + 195, y + 12); cairo_show_text(cr, tmp);
        cairo_move_to(cr, MARGIN + 265, y + 12); cairo_show_text(cr, sb);
        cairo_move_to(cr, MARGIN + 340, y + 12); cairo_show_text(cr, rb);
        snprintf(tmp, sizeof(tmp), "%u / %u", h->syn_sent, h->rst_count);
        cairo_move_to(cr, MARGIN + 415, y + 12); cairo_show_text(cr, tmp);
        y += 18.0;
    }

    /* Lista przeanalizowanych plików na dole strony 1 */
    y = PAGE_H - 125.0;
    draw_section_title(cr, y, "Analyzed Capture Files");
    y += 16.0;
    cairo_select_font_face(cr, "DejaVu Sans", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
    cairo_set_font_size(cr, 8.0);
    cairo_set_source_rgb(cr, 0.35, 0.40, 0.48);
    int show_f = res->file_count < 4 ? res->file_count : 4;
    for (int i = 0; i < show_f; i++) {
        char fbuf[300];
        snprintf(fbuf, sizeof(fbuf), "- %s", res->files[i]);
        cairo_move_to(cr, MARGIN + 6, y + i * 12.0);
        cairo_show_text(cr, fbuf);
    }

    cairo_show_page(cr);
}

static void render_page_charts(cairo_t *cr, const AnalysisResult *res) {
    draw_header(cr, "Visual Traffic Characteristics & Protocol Telemetry", 2, 3);

    double usable_w = PAGE_W - 2 * MARGIN;
    double half_w = (usable_w - 12.0) / 2.0;

    draw_chart_timeline(cr, MARGIN, 78.0, usable_w, 220.0, res);

    draw_chart_protocols(cr, MARGIN,                312.0, half_w, 225.0, res);
    draw_chart_packet_sizes(cr, MARGIN + half_w + 12.0, 312.0, half_w, 225.0, res);

    draw_chart_top_ports(cr, MARGIN,                551.0, half_w, 235.0, res);
    draw_chart_tcp_flags(cr, MARGIN + half_w + 12.0, 551.0, half_w, 235.0, res);

    cairo_show_page(cr);
}

static void render_page_anomalies(cairo_t *cr, const AnalysisResult *res) {
    draw_header(cr, "Security Findings, Anomalies & Dominant Flows", 3, 3);

    double y = 88.0;
    draw_section_title(cr, y, "3. Detected Anomalies & Potential Irregularities");
    y += 18.0;

    if (res->anomaly_count == 0) {
        cairo_set_source_rgb(cr, 0.92, 0.99, 0.94);
        cairo_rectangle(cr, MARGIN, y, PAGE_W - 2 * MARGIN, 34.0);
        cairo_fill(cr);
        cairo_set_source_rgb(cr, 0.08, 0.64, 0.29);
        cairo_set_line_width(cr, 1.0);
        cairo_rectangle(cr, MARGIN, y, PAGE_W - 2 * MARGIN, 34.0);
        cairo_stroke(cr);

        cairo_select_font_face(cr, "DejaVu Sans", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_BOLD);
        cairo_set_font_size(cr, 9.5);
        cairo_move_to(cr, MARGIN + 12.0, y + 21.0);
        cairo_show_text(cr, "OK: No significant traffic anomalies or suspicious patterns detected.");
        y += 50.0;
    } else {
        size_t max_a = res->anomaly_count < 8 ? res->anomaly_count : 8;
        for (size_t i = 0; i < max_a; i++) {
            const Anomaly *a = &res->anomalies[i];
            double br = 0.15, bg = 0.39, bb = 0.92;
            const char *sev_txt = "LOW";
            if (a->severity == SEV_HIGH) {
                br = 0.86; bg = 0.15; bb = 0.15;
                sev_txt = "HIGH";
            } else if (a->severity == SEV_MEDIUM) {
                br = 0.85; bg = 0.47; bb = 0.02;
                sev_txt = "MEDIUM";
            }

            cairo_set_source_rgb(cr, 0.985, 0.99, 0.998);
            cairo_rectangle(cr, MARGIN, y, PAGE_W - 2 * MARGIN, 38.0);
            cairo_fill(cr);
            cairo_set_source_rgb(cr, 0.85, 0.88, 0.92);
            cairo_set_line_width(cr, 0.7);
            cairo_rectangle(cr, MARGIN, y, PAGE_W - 2 * MARGIN, 38.0);
            cairo_stroke(cr);

            /* Badge ważności */
            cairo_set_source_rgb(cr, br, bg, bb);
            cairo_rectangle(cr, MARGIN + 8.0, y + 7.0, 46.0, 14.0);
            cairo_fill(cr);

            cairo_select_font_face(cr, "DejaVu Sans", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_BOLD);
            cairo_set_font_size(cr, 7.2);
            cairo_set_source_rgb(cr, 1.0, 1.0, 1.0);
            cairo_move_to(cr, MARGIN + 14.0, y + 16.5);
            cairo_show_text(cr, sev_txt);

            /* Tytuł i kategoria */
            cairo_set_font_size(cr, 9.0);
            cairo_set_source_rgb(cr, 0.12, 0.16, 0.23);
            char head[160];
            snprintf(head, sizeof(head), "[%s] %s", a->category, a->title);
            cairo_move_to(cr, MARGIN + 62.0, y + 17.0);
            cairo_show_text(cr, head);

            /* Szczegóły */
            cairo_select_font_face(cr, "DejaVu Sans", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
            cairo_set_font_size(cr, 7.8);
            cairo_set_source_rgb(cr, 0.35, 0.40, 0.48);
            cairo_move_to(cr, MARGIN + 62.0, y + 30.5);
            cairo_show_text(cr, a->details);

            y += 43.0;
        }
    }

    /* Sekcja 4: Największe przepływy (Top Flows) */
    if (y < 450.0) y = 450.0;
    draw_section_title(cr, y, "4. Top Network Flows (by Traffic Volume)");
    y += 18.0;

    cairo_set_source_rgb(cr, 0.93, 0.95, 0.98);
    cairo_rectangle(cr, MARGIN, y, PAGE_W - 2 * MARGIN, 20.0);
    cairo_fill(cr);

    cairo_select_font_face(cr, "DejaVu Sans", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_BOLD);
    cairo_set_font_size(cr, 8.0);
    cairo_set_source_rgb(cr, 0.20, 0.25, 0.33);
    cairo_move_to(cr, MARGIN + 6,   y + 13); cairo_show_text(cr, "Source");
    cairo_move_to(cr, MARGIN + 150, y + 13); cairo_show_text(cr, "Destination");
    cairo_move_to(cr, MARGIN + 295, y + 13); cairo_show_text(cr, "Proto");
    cairo_move_to(cr, MARGIN + 340, y + 13); cairo_show_text(cr, "Packets");
    cairo_move_to(cr, MARGIN + 400, y + 13); cairo_show_text(cr, "Volume");
    cairo_move_to(cr, MARGIN + 465, y + 13); cairo_show_text(cr, "Duration");
    y += 20.0;

    cairo_select_font_face(cr, "DejaVu Sans", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
    size_t max_fl = res->flow_count < 14 ? res->flow_count : 14;
    for (size_t i = 0; i < max_fl && y < PAGE_H - 52.0; i++) {
        const FlowStat *f = &res->flows[i];
        char sip[32], dip[32], s_ep[48], d_ep[48], vbuf[32], tmp[32];
        format_ip(f->src_ip, sip, sizeof(sip));
        format_ip(f->dst_ip, dip, sizeof(dip));
        snprintf(s_ep, sizeof(s_ep), "%s:%u", sip, f->src_port);
        snprintf(d_ep, sizeof(d_ep), "%s:%u", dip, f->dst_port);
        format_bytes(f->bytes, vbuf, sizeof(vbuf));

        if (i % 2 == 1) {
            cairo_set_source_rgb(cr, 0.98, 0.985, 0.995);
            cairo_rectangle(cr, MARGIN, y, PAGE_W - 2 * MARGIN, 17.0);
            cairo_fill(cr);
        }

        cairo_set_source_rgb(cr, 0.15, 0.20, 0.28);
        cairo_move_to(cr, MARGIN + 6,   y + 12); cairo_show_text(cr, s_ep);
        cairo_move_to(cr, MARGIN + 150, y + 12); cairo_show_text(cr, d_ep);
        cairo_move_to(cr, MARGIN + 295, y + 12); cairo_show_text(cr, f->proto == PROTO_TCP ? "TCP" : "UDP");
        snprintf(tmp, sizeof(tmp), "%llu", (unsigned long long)f->packets);
        cairo_move_to(cr, MARGIN + 340, y + 12); cairo_show_text(cr, tmp);
        cairo_move_to(cr, MARGIN + 400, y + 12); cairo_show_text(cr, vbuf);
        snprintf(tmp, sizeof(tmp), "%.2fs", f->last_seen - f->first_seen);
        cairo_move_to(cr, MARGIN + 465, y + 12); cairo_show_text(cr, tmp);
        y += 17.0;
    }

    cairo_show_page(cr);
}

int generate_pdf_report(const AnalysisResult *res, const char *pdf_path) {
    cairo_surface_t *surface = cairo_pdf_surface_create(pdf_path, PAGE_W, PAGE_H);
    cairo_status_t st = cairo_surface_status(surface);
    if (st != CAIRO_STATUS_SUCCESS) {
        fprintf(stderr, "[ERROR] Cannot create PDF '%s': %s\n", pdf_path, cairo_status_to_string(st));
        cairo_surface_destroy(surface);
        return -1;
    }

    cairo_t *cr = cairo_create(surface);

    render_page_summary(cr, res);
    render_page_charts(cr, res);
    render_page_anomalies(cr, res);

    cairo_destroy(cr);
    cairo_surface_finish(surface);
    st = cairo_surface_status(surface);
    cairo_surface_destroy(surface);

    if (st != CAIRO_STATUS_SUCCESS) {
        fprintf(stderr, "[ERROR] Error finalizing PDF '%s': %s\n", pdf_path, cairo_status_to_string(st));
        return -1;
    }
    return 0;
}