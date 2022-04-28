#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Author : Quentin Le Ray, Ryan Sauge
# Date : 28.04.2022
# Description : Aircrack version Scapy

from scapy.all import *
from scapy.layers.eap import EAPOL

# Get MIC of last 4-way handshake message

last4way = rdpcap("wpa_handshake.cap")[7]

print(last4way.summary())

mic = last4way.load[77:77 + 16]
print(mic.hex())



#read wordlist file
with open('wordlist.txt') as f:
    for line in f:
        print(line)
