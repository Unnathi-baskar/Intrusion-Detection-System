# SYN Flood Detection with SSL Logging

## Prerequisites

```bash
sudo apt update
sudo apt install libpcap-dev libssl-dev openssl
```

## Compile the C Code

```bash
gcc syn_flood_detect.c -o syn_flood_detect -lpcap -lssl -lcrypto
```

## Start the SSL Server (On Ubuntu VM)

```bash
openssl s_server -accept 4433 -cert server.crt -key server.key -CAfile ca.crt -verify 1
```

## Run the Detector

```bash
sudo ./syn_flood_detect
```

## Simulate SYN Flood (on another machine)

```bash
hping3 -S -p 4433 --flood 172.20.10.3
```
