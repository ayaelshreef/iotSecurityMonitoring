from scapy.all import sniff
import threading

captured_packets = []

def packet_callback(packet):
    global captured_packets
    captured_packets.append(packet.summary())

def start_sniffing():
    sniff(prn=packet_callback, store=0)