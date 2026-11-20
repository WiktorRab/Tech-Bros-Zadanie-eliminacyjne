#ifndef CHARTS_H
#define CHARTS_H

#include <cairo.h>
#include "types.h"

void draw_chart_timeline(cairo_t *cr, double x, double y, double w, double h, const AnalysisResult *res);
void draw_chart_protocols(cairo_t *cr, double x, double y, double w, double h, const AnalysisResult *res);
void draw_chart_top_ports(cairo_t *cr, double x, double y, double w, double h, const AnalysisResult *res);
void draw_chart_packet_sizes(cairo_t *cr, double x, double y, double w, double h, const AnalysisResult *res);
void draw_chart_tcp_flags(cairo_t *cr, double x, double y, double w, double h, const AnalysisResult *res);

int generate_all_png_charts(const AnalysisResult *res, const char *out_dir);

#endif /* CHARTS_H */