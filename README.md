---
This lab is a student project.
It should not be used outside the educational framework.
---

# 802.11 WPA Security

* Extract from a Wireshark capture the data needed to derive WPA encryption and integrity keys using Scapy
* Code your own version of the software [aircrack](https://www.aircrack-ng.org) to find the passphrase of a WPA network from a capture using Python and Scapy
* From a Wireshark capture, extract the PMKID value using Scapy and use it to crack the WPA passphrase

Files

| Files                                   | Description                                   |
| --------------------------------------- | --------------------------------------------- |
| [pmkid attack](./files/pmkid_attack.py) | Implementation of the PMKID attack with scapy |
| [scaircrack.py](./files/scaircrack.py)  | Aircrack version with Scapy                   |