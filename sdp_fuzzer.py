import sys, os, subprocess
import json, datetime
import bluetooth
from statemachine import StateMachine, State
from scapy.all import *
from scapy.packet import Packet
from random import *
from collections import OrderedDict
from scapy.layers.bluetooth import L2CAP_Hdr
import struct
from sdp_packet import *


current_tranid = 0x0001


def sdp_fuzzing(bt_addr, test_info):
    print("SDP fuzzing WIP")
    
    try:
        print("Testing")
        
        service_uuids = [ASSIGNED_SERVICE_UUID["Public Browse Group"]]
        sdp_packet = build_sdp_search_request(current_tranid, 0xFFFF, service_uuids)
        print("Crafted packet bytes:", sdp_packet.hex())
        print("Breakdown:")
        print(f"PDU Header: {sdp_packet[0:5].hex()} (PDU ID, TID, plen)")
        print(f"DES Header: {sdp_packet[5:8].hex()} (0x35, DES length)")
        print(f"Data Element: {sdp_packet[8:11].hex()} (Type, UUID)")
        print(f"Footer: {sdp_packet[11:].hex()} (Max records, Continuation)")
        # Build service search pattern
        


        sock = bluetooth.BluetoothSocket(bluetooth.L2CAP)
        sock.settimeout(5)
        sock.connect((bt_addr, 1))  # SDP channel
        
        sock.send(sdp_packet)
        print("\n[+] Sent SDP request to target device")
        
        # Receive response
        response = sock.recv(4096)
        print(f"\n[+] Received SDP response: {response}")     
        parse_sdp_response(response)
    except Exception as e:
       print(e)