#include "types.h"
#include "parser.h"
#include "analyzer.h"
#include "charts.h"
#include "report.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void print_usage(const char *prog) {
    fprintf(stderr,
            "Usage: %s [-o output_dir] <file1.pcap> [file2.pcap ...]\n"
            "Options:\n"
            "  -o <dir>   Output directory for PDF report and PNG charts (default: ./output)\n"
            "  -h         Show this help message\n",
            prog);
}

static int ensure_dir(const char *dir) {
    if (mkdir(dir, 0755) == -1 && errno != EEXIST) {
        perror("[ERROR] mkdir");
        return -1;
    }
    return 0;
}

int main(int argc, char **argv) {
    const char *out_dir = "output";
    int opt;

    while ((opt = getopt(argc, argv, "o:h")) != -1) {
        switch (opt) {
            case 'o':
                out_dir = optarg;
                break;
            case 'h':
            default:
                print_usage(argv[0]);
                return (opt == 'h') ? 0 : 1;
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "[ERROR] No .pcap input files specified.\n");
        print_usage(argv[0]);
        return 1;
    }

    if (ensure_dir(out_dir) != 0) {
        return 1;
    }

    AnalysisResult res;
    if (analyzer_init(&res) != 0) {
        fprintf(stderr, "[ERROR] Out of memory during initialization.\n");
        return 1;
    }

    int parsed_ok = 0;
    for (int i = optind; i < argc; i++) {
        printf("[INFO] Parsing %s ...\n", argv[i]);
        if (parse_pcap_file(argv[i], &res) == 0) {
            parsed_ok++;
        }
    }

    if (parsed_ok == 0) {
        fprintf(stderr, "[ERROR] Failed to parse any input file.\n");
        analyzer_free(&res);
        return 1;
    }

    analyzer_finalize(&res);

    char vol_buf[32];
    format_bytes(res.total_bytes, vol_buf, sizeof(vol_buf));

    printf("\n=== Analysis Summary ===\n");
    printf("Packets:   %llu (TCP: %llu, UDP: %llu, Other: %llu)\n",
           (unsigned long long)res.total_packets,
           (unsigned long long)res.tcp_packets,
           (unsigned long long)res.udp_packets,
           (unsigned long long)res.other_packets);
    printf("Volume:    %s  |  Duration: %.2f s\n", vol_buf, res.duration);
    printf("Hosts:     %zu  |  Flows: %zu  |  Anomalies: %zu\n",
           res.host_count, res.flow_count, res.anomaly_count);

    for (size_t i = 0; i < res.anomaly_count; i++) {
        const char *sev = res.anomalies[i].severity == SEV_HIGH ? "HIGH" :
                          res.anomalies[i].severity == SEV_MEDIUM ? "MEDIUM" : "LOW";
        printf("  [%s] %s: %s\n", sev, res.anomalies[i].title, res.anomalies[i].details);
    }

    printf("\n[INFO] Generating PNG charts in '%s/' ...\n", out_dir);
    if (generate_all_png_charts(&res, out_dir) != 0) {
        analyzer_free(&res);
        return 1;
    }

    char pdf_path[512];
    snprintf(pdf_path, sizeof(pdf_path), "%s/report.pdf", out_dir);
    printf("[INFO] Generating PDF report '%s' ...\n", pdf_path);
    if (generate_pdf_report(&res, pdf_path) != 0) {
        analyzer_free(&res);
        return 1;
    }

    printf("[DONE] Report and PNG charts generated successfully in '%s/'.\n", out_dir);
    analyzer_free(&res);
    return 0;
}