# What is Spades Firewall?
Spades Firewall is a simple firewall for AoS that protect your server against flood attacks AKA aloha.pk marketing.

Requisites
-------------------------------
- [`libpcap`](https://github.com/the-tcpdump-group/libpcap)

## Getting Started
1. ```apt-get update && apt-get install gcc libpcap0.8* -y```
2. ```git clone https://github.com/RealAtom/spadesfwall.git```
3. ```cd spadesfwall```
4. ```make```

## Usage
```./spadesfwall <iface>```