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
packet_count = 0
crash_count = 0
'''
		pkt_info["no"] = pkt_cnt
		pkt_info["protocol"] = "L2CAP"
		pkt_info["sended_time"] = str(datetime.now())
		pkt_info["payload"] = log_pkt(pkt)
		pkt_info["crash"] = "n"
		pkt_info["l2cap_state"] = state
'''
def send_sdp_packet(bt_addr, sock, packet, packet_type, process_resp=False):
	global packet_count
	packet_count += 1
	packet_info = ""
	try:
		sock.connect((bt_addr, 1))
		sock.send(packet)
		packet_info = {}
		packet_info["no"] = packet_count
		packet_info["protocol"] = "SDP"
		packet_info["sent_time"] = str(datetime.now())
		packet_info["packet_type"] = packet_type
		packet_info["raw_packet"] = packet
		packet_info["crash"] = False
		if process_resp:
			response = sock.recv(4096)
			packet_info["response_data"] = response
	except ConnectionResetError:
		print ("Connection Reset error")
	except ConnectionRefusedError:
		print ("Connection Refused")
	except ConnectionAbortedError:
		print ("Connection Aborted")
	except TimeoutError:
		print ("Connection Timeout")
		pass
	except OSError as e:
		pass
	
	sock = bluetooth.BluetoothSocket(bluetooth.L2CAP)
	return sock, packet_info


def sdp_fuzzing(bt_addr, test_info):
	global current_tranid
	with open('sdp_log_{}.wfl'.format(test_info["starting_time"][11:19].replace(':',"",2)), 'w', encoding="utf-8") as f:
		logger = OrderedDict()
		logger.update(test_info)
		logger["packet"] = []
		print("Start Fuzzing... Please hit Ctrl + C to finish...")
		try:
			service_uuids = [ASSIGNED_SERVICE_UUID["Public Browse Group"]]
			#sdp_packet = build_sdp_search_request(current_tranid, 0xFFFF, service_uuids)
			param_dict = sdp_packet = build_sdp_service_search_attr_request(current_tranid, service_uuids, 0xFFFF, [{"attribute_id":(0x0001 << 16) | 0xFFFF, "isRange": True}])
			current_tranid += 1
			# print("Crafted packet bytes:", sdp_packet.hex())
			# print("Breakdown:")
			# print(f"PDU Header: {sdp_packet[0:5].hex()} (PDU ID, TID, plen)")
			# print(f"DES Header: {sdp_packet[5:8].hex()} (0x35, DES length)")
			# print(f"Data Element: {sdp_packet[8:11].hex()} (Type, UUID)")
			# print(f"Footer: {sdp_packet[11:].hex()} (Max records, Continuation)")
			# # Build service search pattern
			


			sock = bluetooth.BluetoothSocket(bluetooth.L2CAP)
			sock, packet_info = send_sdp_packet(bt_addr, sock, sdp_packet, 0x02, True)
			packet_info["params"] = param_dict
			if packet_info != "":
				logger["packet"].append(packet_info)
   
   
			print(f"\n[+] Received SDP response: {packet_info["response_data"]}")	 
			resp_data = parse_sdp_response(packet_info["response_data"])
			# if resp_data["handle_list"] is not None:
			# 	if len(resp_data["handle_list"]) > 0:
			# 		first_handle = resp_data["handle_list"][0]
			# 		attr_range = (0x0001 << 16) | 0xFFFF
			# 		sdp_packet2 = build_sdp_service_attr_request_by_ranges(current_tranid,first_handle,0xFFFF,[{"attribute_id": attr_range, "isRange": True}])
			# 		sock, packet_info = send_sdp_packet(bt_addr, sock, sdp_packet2, 0x04, True)
			# 		if packet_info != "":
			# 			logger["packet"].append(packet_info)
			# 		#print(packet_info["response_data"])
			print(f"{logger}")
		except Exception as e:
			print("[!] Error Message :", e)
			print("[+] Save logfile")
			logger["end_time"] = str(datetime.now())
			logger["count"] = {"all" : packet_count, "crash" : crash_count, "passed" : packet_count-crash_count}
			#json.dump(logger, f, indent="\t")

		except KeyboardInterrupt as k:
			print("[!] Fuzzing Stopped :", k)
			print("[+] Save logfile")
			logger["end_time"] = str(datetime.now())
			logger["count"] = {"all" : packet_count, "crash" : crash_count, "passed" : packet_count-crash_count}
			#json.dump(logger, f, indent="\t")
		finally:
			json.dump(logger, f, indent="\t")
			
	
