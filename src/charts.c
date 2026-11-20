#include "charts.h"
#include "analyzer.h"

#include <math.h>
#include <stdio.h>
#include <string.h>

#define PI_VAL 3.14159265358979323846

static void draw_card_bg(cairo_t *cr, double x, double y, double w, double h, const char *title) {
    cairo_save(cr);

    /* Tło karty */
    cairo_set_source_rgb(cr, 0.99, 0.995, 1.0);
    cairo_rectangle(cr, x, y, w, h);
    cairo_fill(cr);

    /* Obramowanie */
    cairo_set_source_rgb(cr, 0.85, 0.88, 0.92);
    cairo_set_line_width(cr, 1.0);
    cairo_rectangle(cr, x + 0.5, y + 0.5, w - 1.0, h - 1.0);
    cairo_stroke(cr);

    /* Tytuł wykresu */
    cairo_select_font_face(cr, "DejaVu Sans", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_BOLD);
    cairo_set_font_size(cr, h > 300 ? 15.0 : 10.5);
    cairo_set_source_rgb(cr, 0.12, 0.16, 0.23);
    cairo_move_to(cr, x + 14.0, y + (h > 300 ? 26.0 : 18.0));
    cairo_show_text(cr, title);

    cairo_restore(cr);
}

static void draw_text_right(cairo_t *cr, double x, double y, const char *text) {
    cairo_text_extents_t ext;
    cairo_text_extents(cr, text, &ext);
    cairo_move_to(cr, x - ext.width - ext.x_bearing, y);
    cairo_show_text(cr, text);
}

static void draw_text_center(cairo_t *cr, double cx, double y, const char *text) {
    cairo_text_extents_t ext;
    cairo_text_extents(cr, text, &ext);
    cairo_move_to(cr, cx - ext.width / 2.0 - ext.x_bearing, y);
    cairo_show_text(cr, text);
}

void draw_chart_timeline(cairo_t *cr, double x, double y, double w, double h, const AnalysisResult *res) {
    draw_card_bg(cr, x, y, w, h, "Traffic Intensity Over Time (TCP vs UDP)");
    cairo_save(cr);

    double pad_l = w > 600 ? 58.0 : 42.0;
    double pad_r = 20.0;
    double pad_t = h > 300 ? 48.0 : 32.0;
    double pad_b = h > 300 ? 42.0 : 28.0;

    double px = x + pad_l;
    double py = y + pad_t;
    double pw = w - pad_l - pad_r;
    double ph = h - pad_t - pad_b;
    double font_sz = h > 300 ? 11.0 : 8.0;

    uint64_t max_pkts = 1;
    for (int i = 0; i < TIMELINE_BUCKETS; i++) {
        uint64_t m = res->timeline[i].tcp_pkts > res->timeline[i].udp_pkts
                     ? res->timeline[i].tcp_pkts : res->timeline[i].udp_pkts;
        if (m > max_pkts) max_pkts = m;
    }

    /* Siatka pozioma + etykiety Y */
    cairo_select_font_face(cr, "DejaVu Sans", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
    cairo_set_font_size(cr, font_sz);
    double dashes[] = {3.0, 3.0};

    for (int i = 0; i <= 4; i++) {
        double gy = py + ph - (ph * i / 4.0);
        cairo_set_source_rgb(cr, 0.88, 0.90, 0.94);
        cairo_set_line_width(cr, 0.8);
        cairo_set_dash(cr, dashes, 2, 0.0);
        cairo_move_to(cr, px, gy);
        cairo_line_to(cr, px + pw, gy);
        cairo_stroke(cr);
        cairo_set_dash(cr, NULL, 0, 0.0);

        char lbl[32];
        snprintf(lbl, sizeof(lbl), "%llu", (unsigned long long)((max_pkts * (uint64_t)i) / 4));
        cairo_set_source_rgb(cr, 0.40, 0.45, 0.53);
        draw_text_right(cr, px - 6.0, gy + 3.0, lbl);
    }

    /* Osie */
    cairo_set_source_rgb(cr, 0.55, 0.60, 0.68);
    cairo_set_line_width(cr, 1.0);
    cairo_move_to(cr, px, py);
    cairo_line_to(cr, px, py + ph);
    cairo_line_to(cr, px + pw, py + ph);
    cairo_stroke(cr);

    double step = pw / (double)(TIMELINE_BUCKETS - 1);

    /* Wypełnienie pod linią TCP */
    cairo_set_source_rgba(cr, 0.15, 0.39, 0.92, 0.14);
    cairo_move_to(cr, px, py + ph);
    for (int i = 0; i < TIMELINE_BUCKETS; i++) {
        double cx = px + i * step;
        double cy = py + ph - ((double)res->timeline[i].tcp_pkts / (double)max_pkts) * ph;
        cairo_line_to(cr, cx, cy);
    }
    cairo_line_to(cr, px + pw, py + ph);
    cairo_close_path(cr);
    cairo_fill(cr);

    /* Linia TCP */
    cairo_set_source_rgb(cr, 0.15, 0.39, 0.92);
    cairo_set_line_width(cr, h > 300 ? 2.2 : 1.6);
    for (int i = 0; i < TIMELINE_BUCKETS; i++) {
        double cx = px + i * step;
        double cy = py + ph - ((double)res->timeline[i].tcp_pkts / (double)max_pkts) * ph;
        if (i == 0) cairo_move_to(cr, cx, cy);
        else        cairo_line_to(cr, cx, cy);
    }
    cairo_stroke(cr);

    /* Wypełnienie pod linią UDP */
    cairo_set_source_rgba(cr, 0.05, 0.58, 0.53, 0.14);
    cairo_move_to(cr, px, py + ph);
    for (int i = 0; i < TIMELINE_BUCKETS; i++) {
        double cx = px + i * step;
        double cy = py + ph - ((double)res->timeline[i].udp_pkts / (double)max_pkts) * ph;
        cairo_line_to(cr, cx, cy);
    }
    cairo_line_to(cr, px + pw, py + ph);
    cairo_close_path(cr);
    cairo_fill(cr);

    /* Linia UDP */
    cairo_set_source_rgb(cr, 0.05, 0.58, 0.53);
    cairo_set_line_width(cr, h > 300 ? 2.2 : 1.6);
    for (int i = 0; i < TIMELINE_BUCKETS; i++) {
        double cx = px + i * step;
        double cy = py + ph - ((double)res->timeline[i].udp_pkts / (double)max_pkts) * ph;
        if (i == 0) cairo_move_to(cr, cx, cy);
        else        cairo_line_to(cr, cx, cy);
    }
    cairo_stroke(cr);

    /* Etykiety osi X (czas) */
    cairo_set_source_rgb(cr, 0.40, 0.45, 0.53);
    for (int i = 0; i <= 4; i++) {
        double tx = px + (pw * i / 4.0);
        double sec = res->duration * i / 4.0;
        char lbl[32];
        snprintf(lbl, sizeof(lbl), "+%.1fs", sec);
        draw_text_center(cr, tx, py + ph + (h > 300 ? 18.0 : 12.0), lbl);
    }

    /* Legenda */
    double lx = x + w - (w > 600 ? 155.0 : 115.0);
    double ly = y + (h > 300 ? 22.0 : 15.0);
    cairo_set_source_rgb(cr, 0.15, 0.39, 0.92);
    cairo_rectangle(cr, lx, ly - 6.0, 10.0, 6.0);
    cairo_fill(cr);
    cairo_set_source_rgb(cr, 0.20, 0.25, 0.33);
    cairo_move_to(cr, lx + 14.0, ly);
    cairo_show_text(cr, "TCP");

    cairo_set_source_rgb(cr, 0.05, 0.58, 0.53);
    cairo_rectangle(cr, lx + 52.0, ly - 6.0, 10.0, 6.0);
    cairo_fill(cr);
    cairo_set_source_rgb(cr, 0.20, 0.25, 0.33);
    cairo_move_to(cr, lx + 66.0, ly);
    cairo_show_text(cr, "UDP");

    cairo_restore(cr);
}

void draw_chart_protocols(cairo_t *cr, double x, double y, double w, double h, const AnalysisResult *res) {
    draw_card_bg(cr, x, y, w, h, "Protocol Distribution (Packets)");
    cairo_save(cr);

    double cx = x + w * 0.34;
    double cy = y + h * 0.56;
    double radius = (w * 0.28 < h * 0.34) ? w * 0.28 : h * 0.34;
    double inner_r = radius * 0.54;
    double font_sz = h > 300 ? 12.0 : 8.5;

    uint64_t vals[3] = { res->tcp_packets, res->udp_packets, res->other_packets };
    const char *names[3] = { "TCP", "UDP", "Other" };
    double colors[3][3] = {
        {0.15, 0.39, 0.92},
        {0.05, 0.58, 0.53},
        {0.85, 0.47, 0.02}
    };

    if (res->total_packets == 0) {
        cairo_set_source_rgb(cr, 0.85, 0.88, 0.92);
        cairo_arc(cr, cx, cy, radius, 0, 2.0 * PI_VAL);
        cairo_fill(cr);
    } else {
        double angle = -PI_VAL / 2.0;
        for (int i = 0; i < 3; i++) {
            if (vals[i] == 0) continue;
            double sweep = 2.0 * PI_VAL * ((double)vals[i] / (double)res->total_packets);
            cairo_set_source_rgb(cr, colors[i][0], colors[i][1], colors[i][2]);
            cairo_move_to(cr, cx, cy);
            cairo_arc(cr, cx, cy, radius, angle, angle + sweep);
            cairo_close_path(cr);
            cairo_fill(cr);
            angle += sweep;
        }
    }

    /* Wycięcie donut */
    cairo_set_source_rgb(cr, 0.99, 0.995, 1.0);
    cairo_arc(cr, cx, cy, inner_r, 0, 2.0 * PI_VAL);
    cairo_fill(cr);

    /* Suma w środku */
    cairo_select_font_face(cr, "DejaVu Sans", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_BOLD);
    cairo_set_font_size(cr, h > 300 ? 14.0 : 9.5);
    cairo_set_source_rgb(cr, 0.12, 0.16, 0.23);
    char total_lbl[32];
    snprintf(total_lbl, sizeof(total_lbl), "%llu", (unsigned long long)res->total_packets);
    draw_text_center(cr, cx, cy + 2.0, total_lbl);

    cairo_select_font_face(cr, "DejaVu Sans", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
    cairo_set_font_size(cr, h > 300 ? 10.0 : 7.0);
    cairo_set_source_rgb(cr, 0.45, 0.50, 0.58);
    draw_text_center(cr, cx, cy + (h > 300 ? 16.0 : 11.0), "packets");

    /* Legenda po prawej */
    double lx = x + w * 0.64;
    double ly = y + h * 0.36;
    double row_h = h > 300 ? 34.0 : 22.0;

    for (int i = 0; i < 3; i++) {
        double pct = res->total_packets > 0
                     ? 100.0 * (double)vals[i] / (double)res->total_packets : 0.0;
        cairo_set_source_rgb(cr, colors[i][0], colors[i][1], colors[i][2]);
        cairo_rectangle(cr, lx, ly + i * row_h - 8.0, 10.0, 10.0);
        cairo_fill(cr);

        cairo_select_font_face(cr, "DejaVu Sans", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_BOLD);
        cairo_set_font_size(cr, font_sz);
        cairo_set_source_rgb(cr, 0.15, 0.20, 0.28);
        char line[64];
        snprintf(line, sizeof(line), "%s: %.1f%%", names[i], pct);
        cairo_move_to(cr, lx + 15.0, ly + i * row_h);
        cairo_show_text(cr, line);

        cairo_select_font_face(cr, "DejaVu Sans", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
        cairo_set_font_size(cr, font_sz - 1.5);
        cairo_set_source_rgb(cr, 0.45, 0.50, 0.58);
        snprintf(line, sizeof(line), "(%llu pkts)", (unsigned long long)vals[i]);
        cairo_move_to(cr, lx + 15.0, ly + i * row_h + (h > 300 ? 13.0 : 9.0));
        cairo_show_text(cr, line);
    }

    cairo_restore(cr);
}

void draw_chart_top_ports(cairo_t *cr, double x, double y, double w, double h, const AnalysisResult *res) {
    draw_card_bg(cr, x, y, w, h, "Top Active Ports / Services");
    cairo_save(cr);

    size_t count = res->port_count < 8 ? res->port_count : 8;
    double font_sz = h > 300 ? 11.0 : 7.8;
    cairo_select_font_face(cr, "DejaVu Sans", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
    cairo_set_font_size(cr, font_sz);

    if (count == 0) {
        cairo_set_source_rgb(cr, 0.45, 0.50, 0.58);
        draw_text_center(cr, x + w / 2.0, y + h / 2.0, "No TCP/UDP ports observed");
        cairo_restore(cr);
        return;
    }

    double pad_l = w > 600 ? 135.0 : 92.0;
    double pad_r = w > 600 ? 58.0 : 38.0;
    double pad_t = h > 300 ? 46.0 : 30.0;
    double pad_b = 14.0;

    double pw = w - pad_l - pad_r;
    double ph = h - pad_t - pad_b;
    double row_h = ph / (double)count;
    double bar_h = row_h * 0.60;

    uint64_t max_pkts = res->ports[0].packets > 0 ? res->ports[0].packets : 1;

    for (size_t i = 0; i < count; i++) {
        const PortStat *p = &res->ports[i];
        double ry = y + pad_t + i * row_h;
        double bw = ((double)p->packets / (double)max_pkts) * pw;

        char lbl[64];
        snprintf(lbl, sizeof(lbl), "%u/%s (%s)",
                 p->port, p->proto == PROTO_TCP ? "TCP" : "UDP",
                 port_service_name(p->port));
        cairo_set_source_rgb(cr, 0.20, 0.25, 0.33);
        draw_text_right(cr, x + pad_l - 8.0, ry + bar_h * 0.78, lbl);

        if (p->proto == PROTO_TCP) cairo_set_source_rgb(cr, 0.15, 0.39, 0.92);
        else                       cairo_set_source_rgb(cr, 0.05, 0.58, 0.53);

        cairo_rectangle(cr, x + pad_l, ry, bw > 2.0 ? bw : 2.0, bar_h);
        cairo_fill(cr);

        char val[32];
        snprintf(val, sizeof(val), "%llu", (unsigned long long)p->packets);
        cairo_set_source_rgb(cr, 0.35, 0.40, 0.48);
        cairo_move_to(cr, x + pad_l + bw + 5.0, ry + bar_h * 0.78);
        cairo_show_text(cr, val);
    }

    cairo_restore(cr);
}

void draw_chart_packet_sizes(cairo_t *cr, double x, double y, double w, double h, const AnalysisResult *res) {
    draw_card_bg(cr, x, y, w, h, "Packet Size Distribution (Bytes)");
    cairo_save(cr);

    const char *labels[SIZE_BUCKETS] = {
        "<64", "64-127", "128-255", "256-511", "512-1K", "1K-1.5K", ">1.5K"
    };

    double pad_l = w > 600 ? 55.0 : 38.0;
    double pad_r = 16.0;
    double pad_t = h > 300 ? 48.0 : 32.0;
    double pad_b = h > 300 ? 42.0 : 28.0;

    double px = x + pad_l;
    double py = y + pad_t;
    double pw = w - pad_l - pad_r;
    double ph = h - pad_t - pad_b;
    double font_sz = h > 300 ? 10.5 : 7.2;

    uint64_t max_v = 1;
    for (int i = 0; i < SIZE_BUCKETS; i++) {
        if (res->size_buckets[i] > max_v) max_v = res->size_buckets[i];
    }

    cairo_select_font_face(cr, "DejaVu Sans", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
    cairo_set_font_size(cr, font_sz);

    /* Osie */
    cairo_set_source_rgb(cr, 0.55, 0.60, 0.68);
    cairo_set_line_width(cr, 1.0);
    cairo_move_to(cr, px, py);
    cairo_line_to(cr, px, py + ph);
    cairo_line_to(cr, px + pw, py + ph);
    cairo_stroke(cr);

    double slot_w = pw / (double)SIZE_BUCKETS;
    double bar_w = slot_w * 0.62;

    for (int i = 0; i < SIZE_BUCKETS; i++) {
        double bh = ((double)res->size_buckets[i] / (double)max_v) * (ph - 12.0);
        double bx = px + i * slot_w + (slot_w - bar_w) / 2.0;
        double by = py + ph - bh;

        cairo_set_source_rgb(cr, 0.39, 0.40, 0.95);
        cairo_rectangle(cr, bx, by, bar_w, bh);
        cairo_fill(cr);

        if (res->size_buckets[i] > 0) {
            char vbuf[24];
            snprintf(vbuf, sizeof(vbuf), "%llu", (unsigned long long)res->size_buckets[i]);
            cairo_set_source_rgb(cr, 0.25, 0.30, 0.38);
            draw_text_center(cr, bx + bar_w / 2.0, by - 3.0, vbuf);
        }

        cairo_set_source_rgb(cr, 0.35, 0.40, 0.48);
        draw_text_center(cr, bx + bar_w / 2.0, py + ph + (h > 300 ? 16.0 : 11.0), labels[i]);
    }

    cairo_restore(cr);
}

void draw_chart_tcp_flags(cairo_t *cr, double x, double y, double w, double h, const AnalysisResult *res) {
    draw_card_bg(cr, x, y, w, h, "TCP Control Flags & Anomalous Probes");
    cairo_save(cr);

    const char *labels[7] = { "SYN", "SYN-ACK", "ACK", "PSH", "FIN", "RST", "NULL/XMAS" };
    uint64_t vals[7] = {
        res->tcp_flags.syn,
        res->tcp_flags.syn_ack,
        res->tcp_flags.ack,
        res->tcp_flags.psh,
        res->tcp_flags.fin,
        res->tcp_flags.rst,
        res->tcp_flags.null_scan + res->tcp_flags.xmas_scan + res->tcp_flags.syn_fin
    };

    double pad_l = w > 600 ? 55.0 : 38.0;
    double pad_r = 16.0;
    double pad_t = h > 300 ? 48.0 : 32.0;
    double pad_b = h > 300 ? 42.0 : 28.0;

    double px = x + pad_l;
    double py = y + pad_t;
    double pw = w - pad_l - pad_r;
    double ph = h - pad_t - pad_b;
    double font_sz = h > 300 ? 10.5 : 7.0;

    uint64_t max_v = 1;
    for (int i = 0; i < 7; i++) {
        if (vals[i] > max_v) max_v = vals[i];
    }

    cairo_select_font_face(cr, "DejaVu Sans", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
    cairo_set_font_size(cr, font_sz);

    cairo_set_source_rgb(cr, 0.55, 0.60, 0.68);
    cairo_set_line_width(cr, 1.0);
    cairo_move_to(cr, px, py);
    cairo_line_to(cr, px, py + ph);
    cairo_line_to(cr, px + pw, py + ph);
    cairo_stroke(cr);

    double slot_w = pw / 7.0;
    double bar_w = slot_w * 0.58;

    for (int i = 0; i < 7; i++) {
        double bh = ((double)vals[i] / (double)max_v) * (ph - 12.0);
        double bx = px + i * slot_w + (slot_w - bar_w) / 2.0;
        double by = py + ph - bh;

        if (i >= 5)      cairo_set_source_rgb(cr, 0.86, 0.15, 0.15); /* RST / Probes -> czerwony */
        else if (i == 0) cairo_set_source_rgb(cr, 0.85, 0.47, 0.02); /* SYN -> bursztynowy */
        else             cairo_set_source_rgb(cr, 0.15, 0.39, 0.92); /* Pozostałe -> niebieski */

        cairo_rectangle(cr, bx, by, bar_w, bh);
        cairo_fill(cr);

        if (vals[i] > 0) {
            char vbuf[24];
            snprintf(vbuf, sizeof(vbuf), "%llu", (unsigned long long)vals[i]);
            cairo_set_source_rgb(cr, 0.25, 0.30, 0.38);
            draw_text_center(cr, bx + bar_w / 2.0, by - 3.0, vbuf);
        }

        cairo_set_source_rgb(cr, 0.35, 0.40, 0.48);
        draw_text_center(cr, bx + bar_w / 2.0, py + ph + (h > 300 ? 16.0 : 11.0), labels[i]);
    }

    cairo_restore(cr);
}

typedef void (*ChartDrawFn)(cairo_t *, double, double, double, double, const AnalysisResult *);

static int render_png(const char *path, int width, int height, ChartDrawFn fn, const AnalysisResult *res) {
    cairo_surface_t *surface = cairo_image_surface_create(CAIRO_FORMAT_ARGB32, width, height);
    cairo_t *cr = cairo_create(surface);

    cairo_set_source_rgb(cr, 0.95, 0.97, 0.99);
    cairo_paint(cr);

    fn(cr, 16.0, 16.0, (double)width - 32.0, (double)height - 32.0, res);

    cairo_status_t st = cairo_surface_write_to_png(surface, path);
    cairo_destroy(cr);
    cairo_surface_destroy(surface);

    if (st != CAIRO_STATUS_SUCCESS) {
        fprintf(stderr, "[ERROR] Failed writing PNG '%s': %s\n", path, cairo_status_to_string(st));
        return -1;
    }
    return 0;
}

int generate_all_png_charts(const AnalysisResult *res, const char *out_dir) {
    char path[512];
    int rc = 0;

    snprintf(path, sizeof(path), "%s/01_traffic_timeline.png", out_dir);
    rc |= render_png(path, 960, 440, draw_chart_timeline, res);

    snprintf(path, sizeof(path), "%s/02_protocol_distribution.png", out_dir);
    rc |= render_png(path, 760, 440, draw_chart_protocols, res);

    snprintf(path, sizeof(path), "%s/03_top_ports.png", out_dir);
    rc |= render_png(path, 860, 460, draw_chart_top_ports, res);

    snprintf(path, sizeof(path), "%s/04_packet_sizes.png", out_dir);
    rc |= render_png(path, 860, 440, draw_chart_packet_sizes, res);

    snprintf(path, sizeof(path), "%s/05_tcp_flags.png", out_dir);
    rc |= render_png(path, 860, 440, draw_chart_tcp_flags, res);

    return rc;
}