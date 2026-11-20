#ifndef ANALYZER_H
#define ANALYZER_H

#include "types.h"

int  analyzer_init(AnalysisResult *res);
void analyzer_process_packet(AnalysisResult *res, const PacketInfo *pkt);
void analyzer_finalize(AnalysisResult *res);
void analyzer_free(AnalysisResult *res);

void format_ip(uint32_t ip, char *buf, size_t len);
void format_bytes(uint64_t bytes, char *buf, size_t len);
const char *port_service_name(uint16_t port);

#endif /* ANALYZER_H */