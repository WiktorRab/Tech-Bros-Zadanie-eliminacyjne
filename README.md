# NetScope — Analizator ruchu TCP/UDP z plików .pcap

Rozwiązanie zadania eliminacyjnego na hackathon. Narzędzie działa w środowisku Linux, analizuje komunikację TCP i UDP na podstawie dostarczonych plików `.pcap`, wykrywa potencjalne nieprawidłowości oraz generuje raport PDF i zestaw wykresów PNG.

## Wymagane zależności dla działania programu

```bash
sudo apt update
sudo apt install -y build-essential pkg-config libpcap-dev libcairo2-dev fonts-dejavu-core
```

## Wymagane zależności dla nagrywania własnego pliku .pcap

```bash
sudo apt update
sudo apt install -y tcpdump
```

## Kompilacja i generowanie raportu

1. Kompilacja projektu:

```bash
make
```

2. Uruchomienie analizy na pliku `.pcap`:

```bash
./netscope {nazwa_pliku}.pcap
```

3. Uruchomienie wbudowanego testu (generuje syntetyczny plik `samples/demo_traffic.pcap` z ruchem normalnym oraz symulowanymi anomaliami, a następnie tworzy dla niego raport):

```bash
make test
```

## Wyniki działania programu

Domyślnie wszystkie wygenerowane pliki zapisywane są w katalogu `output/` (lub w folderze wskazanym po fladze `-o`):

* `report.pdf` — 3-stronicowy raport zawierający podsumowanie statystyk ruchu, zestawienie najbardziej aktywnych hostów, wykresy oraz listę wykrytych anomalii
* `01_traffic_timeline.png` — natężenie ruchu TCP i UDP w czasie
* `02_protocol_distribution.png` — udział procentowy pakietów według protokołów
* `03_top_ports.png` — najbardziej obciążone porty i usługi
* `04_packet_sizes.png` — rozkład rozmiarów pakietów
* `05_tcp_flags.png` — rozkład flag kontrolnych TCP.