# What is Spades Firewall?
Spades Firewall is a simple firewall for AoS that protect your server against flood attacks AKA aloha.pk marketing.

Requisites
-------------------------------
- [`libpcap`](https://github.com/the-tcpdump-group/libpcap)

## Getting Started
1. ```apt-get update && apt-get install gcc libpcap0.8* -y```
2. ```git clone https://github.com/RealAtom/spades_firewall.git```
3. ```cd spades_firewall```
4. ```make```

## Usage
```./spades <iface>```