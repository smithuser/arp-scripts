# -*- coding: utf-8 -*-
"""
Created on Fri Sep 16 09:58:31 2022

@author: 21030363
"""
import sys
import scapy.all as scapy
import scapy.config as sConf

def get_interface():
    try:
        iface = sys.argv[1]
    except IndexError:
        iface = sConf.conf.iface  
        
    return iface

# A function to sniff packets from an interface
def sniff_packets(interface):
    scapy.sniff(filter= "arp", iface=interface, prn=analyze_packet, store=False)

 
def analyze_packet(packet):
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
        
        try:
            actual_mac = get_MAC(packet[scapy.ARP].psrc)
            packet_mac =packet[scapy.ARP].hwsrc
        
            if actual_mac != packet_mac:
                add_to_iptables(packet_mac)
                print("[-] You are under ARP Spoof Attack!")
                
        except IndexError:
            pass
        
def get_MAC(target_IP):
    arp_request = scapy.ARP(pdst=target_IP) 
    
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    broadcast_arp_request = broadcast/arp_request
    answered_list=scapy.srp(broadcast_arp_request, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc

def add_to_iptables(mac):
    import subprocess

    check = "sudo iptables -C INPUT -m mac --mac-source " + mac + " -j DROP"
    res = subprocess.run([check], shell=True)

    if res.returncode == 1:
        subprocess_str = "/usr/sbin/iptables -A INPUT -m mac --mac-source " + mac +" -j DROP"
        subprocess.run([subprocess_str], shell=True)

        print("%s has been added to the iptables: " % mac)
    else:
        pass

iface = get_interface()
sniff_packets(iface)
