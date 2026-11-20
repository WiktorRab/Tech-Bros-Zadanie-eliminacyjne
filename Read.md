cat << 'EOF' > README.md
# NetScope — Linux TCP/UDP `.pcap` Traffic Analyzer in C

Modularne narzędzie w języku C (C11) dla systemu Linux analizujące komunikację TCP i UDP z jednego lub wielu plików `.pcap`. Program generuje wielostronicowy raport wektorowy **PDF** oraz zestaw wykresów **PNG** ze statystykami ruchu, charakterystyką połączeń i wykrytymi anomaliami.

## Funkcjonalności
- **Obsługa wielu warstw łącza:** Ethernet (w tym tagi VLAN 802.1Q/QinQ), Linux SLL/SLL2, Raw IP, Loopback.
- **Analiza ruchu TCP/UDP:** agregacja hostów (Top Talkers), portów/usług, przepływów (5-tuple), rozkładu rozmiarów pakietów, flag TCP oraz osi czasu.
- **Detekcja anomalii:**
  - skanowanie portów TCP SYN (`SYN` do >=15 unikalnych portów bez odpowiedzi `SYN-ACK`),
  - potencjalny SYN Flood oraz UDP Flood,
  - sondy stealth scan (`NULL`, `XMAS`, nielegalne `SYN+FIN`),
  - podwyższony udział pakietów `RST`,
  - statystyczne skoki natężenia ruchu ($>3\sigma$),
  - uszkodzone/obcięte nagłówki.
- **Raportowanie bez ciężkich zależności:** generowanie zarówno PNG, jak i 3-stronicowego raportu PDF bezpośrednio w C przy użyciu `libcairo`.

## Architektura modułów
- `src/parser.c` — bezpieczne bajtowe dekodowanie ramek i nagłówków IPv4/TCP/UDP (`libpcap`).
- `src/analyzer.c` — tablice haszujące $O(1)$ dla hostów, portów i przepływów oraz silnik detekcji anomalii.
- `src/charts.c` — renderowanie wykresów wektorowych (PNG + komponenty dla PDF).
- `src/report.c` — skład 3-stronicowego raportu PDF (KPI, tabele, wykresy, alerty).
- `src/main.c` — interfejs CLI.
- `tools/gen_sample_pcap.c` — generator syntetycznego pliku `.pcap` (ruch normalny + anomalie) do testów.

## Zależności (Ubuntu / Debian)
```bash
sudo apt update
sudo apt install -y build-essential pkg-config libpcap-dev libcairo2-dev fonts-dejavu-core