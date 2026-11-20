#ifndef PARSER_H
#define PARSER_H

#include "types.h"

int parse_pcap_file(const char *filepath, AnalysisResult *res);

#endif /* PARSER_H */