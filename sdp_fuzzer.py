import sys, os, subprocess
import json, datetime
import bluetooth
from l2cap_fuzzer import *
from scapy.all import *
from scapy.packet import Packet
from random import *
from collections import OrderedDict
from scapy.layers.bluetooth import L2CAP_Hdr
from sdp_packet import *
import traceback

current_tranid = 0x0001
packet_count = 0
crash_count = 0
service_handle_list = []
fuzz_iteration = 10
'''
		packet_info["no"] = pkt_cnt
		packet_info["protocol"] = "L2CAP"
		packet_info["sended_time"] = str(datetime.now())
		packet_info["payload"] = log_pkt(pkt)
		packet_info["crash"] = "n"
		packet_info["l2cap_state"] = state
'''
def send_sdp_packet(bt_addr, sock, packet, packet_type, process_resp=False):
	global packet_count, crash_count
	packet_count += 1
	packet_info = ""
	try:
		#sock.connect((bt_addr, 1))
		sock.send(packet)
		packet_info = {}
		packet_info["no"] = packet_count
		packet_info["protocol"] = "SDP"
		packet_info["sent_time"] = str(datetime.now())
		packet_info["packet_type"] = packet_type
		packet_info["raw_packet"] = packet.hex()
		packet_info["crash"] = "n"
		packet_info["sended?"] = "n"	
		response = b'\x00'
		if process_resp:
			response = sock.recv(4096)
			packet_info["response_data"] = response.hex()
	except ConnectionResetError:
		print("[-] Crash Found - ConnectionResetError detected")
		if(l2ping(bt_addr) == False):
			print("Crash Packet :", packet)
			crash_count += 1
			packet_info = {}
			packet_info["no"] = packet_count
			packet_info["protocol"] = "SDP"
			packet_info["sent_time"] = str(datetime.now())
			packet_info["packet_type"] = packet_type
			packet_info["raw_packet"] = packet.hex()
			packet_info["sended?"] = "n"			
			packet_info["crash"] = "y"
			packet_info["crash_info"] = "ConnectionResetError"

	except ConnectionRefusedError:
		print("[-] Crash Found - ConnectionRefusedError detected")
		if(l2ping(bt_addr) == False):
			print("Crash Packet :", packet)
			crash_count += 1
			packet_info = {}
			packet_info["no"] = packet_count
			packet_info["protocol"] = "SDP"
			packet_info["sent_time"] = str(datetime.now())
			packet_info["packet_type"] = packet_type
			packet_info["raw_packet"] = packet.hex()
			packet_info["sended?"] = "n"			
			packet_info["crash"] = "y"
			packet_info["crash_info"] = "ConnectionRefusedError"

	except ConnectionAbortedError:
		print("[-] Crash Found - ConnectionAbortedError detected")
		if(l2ping(bt_addr) == False):
			print("Crash Packet :", packet)
			crash_count += 1
			packet_info = {}
			packet_info["no"] = packet_count
			packet_info["protocol"] = "SDP"
			packet_info["sent_time"] = str(datetime.now())
			packet_info["packet_type"] = packet_type
			packet_info["raw_packet"] = packet.hex()
			packet_info["sended?"] = "n"			
			packet_info["crash"] = "y"
			packet_info["crash_info"] = "ConnectionAbortedError"		

	except TimeoutError:
		# State Timeout
		print("[-] Crash Found - TimeoutError detected")
		print("Crash Packet :", packet)
		crash_count += 1
		packet_info = {}
		packet_info["no"] = packet_count
		packet_info["protocol"] = "SDP"
		packet_info["sent_time"] = str(datetime.now())
		packet_info["packet_type"] = packet_type
		packet_info["raw_packet"] = packet.hex()
		packet_info["sended?"] = "n"			
		packet_info["crash"] = "y"
		packet_info["crash_info"] = "TimeoutError"

	except OSError as e:
		"""
		OSError: [Errno 107] Transport endpoint is not connected
		OSError: [Errno 112] Host is down
		"""
		if "Host is down" in e.__doc__:
			print("[-] Crash Found - Host is down")
			print("Crash Packet :", packet)
			crash_count += 1
			packet_info = {}
			packet_info["no"] = packet_count
			packet_info["protocol"] = "SDP"
			packet_info["sent_time"] = str(datetime.now())
			packet_info["packet_type"] = packet_type
			packet_info["raw_packet"] = packet.hex()
			packet_info["sended?"] = "n"			
			packet_info["crash"] = "y"
			packet_info["DoS"] = "y"
			packet_info["crash_info"] = "OSError - Host is down"
			print("[-] Crash packet causes HOST DOWN. Test finished.")
		else:
			pass
	
	#sock = bluetooth.BluetoothSocket(bluetooth.L2CAP)
	return sock, packet_info, response

'''
				if(len(logger['packet']) > 200000):
					del logger['packet'][:100000]
     
'''

def send_test_packet(bt_addr,logger):
	global current_tranid
	service_uuids = [ASSIGNED_SERVICE_UUID["Public Browse Group"]]
	#sdp_packet = build_sdp_search_request(current_tranid, 0xFFFF, service_uuids)
	param_dict, sdp_packet = build_sdp_service_search_attr_request(current_tranid, service_uuids, 0xFFFF, [{"attribute_id":(0x0001 << 16) | 0xFFFF, "isRange": True}])
	current_tranid += 1
	# print("Crafted packet bytes:", sdp_packet.hex())
	# print("Breakdown:")
	# print(f"PDU Header: {sdp_packet[0:5].hex()} (PDU ID, TID, plen)")
	# print(f"DES Header: {sdp_packet[5:8].hex()} (0x35, DES length)")
	# print(f"Data Element: {sdp_packet[8:11].hex()} (Type, UUID)")
	# print(f"Footer: {sdp_packet[11:].hex()} (Max records, Continuation)")
	# # Build service search pattern
	


	sock = bluetooth.BluetoothSocket(bluetooth.L2CAP)
	sock.connect((bt_addr, 1))
	sock, packet_info, response = send_sdp_packet(bt_addr, sock, sdp_packet, 0x02, True)
	
	if packet_info != "":
		packet_info["params"] = param_dict
		logger["packet"].append(packet_info)



	resp_data = parse_sdp_response(response)
	if resp_data["continuation_state"] != b"\x00":
		print(f"Continuation state: {resp_data["continuation_state"]}")
		param_dict, sdp_packet = build_sdp_service_search_attr_request(current_tranid, service_uuids, 0xFFFF, [{"attribute_id":(0x0001 << 16) | 0xFFFF, "isRange": True}], resp_data["continuation_state"])
		sock, packet_info, response = send_sdp_packet(bt_addr, sock, sdp_packet, 0x02, True)
		
		if packet_info != "":
			packet_info["param_dict"] = param_dict
			logger["packet"].append(packet_info)


def send_initial_sdp_service_search(bt_add, sock, logger):
	global current_tranid
	global service_handle_list
	param_dict, packet = build_sdp_search_request(current_tranid, 0xFF, [ASSIGNED_SERVICE_UUID["Public Browse Group"]])
	sock, packet_info, response = send_sdp_packet(bt_addr=bt_add, sock=sock, packet=packet, packet_type=0x02, process_resp=True)
	if packet_info != "":
		packet_info["params"] = param_dict
		logger["packet"].append(packet_info)
		if response != b'\x00':
			resp = parse_sdp_response(response)
			if resp["handle_list"] is not None:
				service_handle_list = resp["handle_list"]
	if len(service_handle_list) == 0: #in case no service handle
		service_handle_list.append[b'\x1001']
	print(f"Current service handle list: {service_handle_list}")

	current_tranid = (current_tranid + 1) % 0x10000

def fuzz_sdp_service_attr(bt_addr, sock, logger):
	global current_tranid
	global fuzz_iteration
	global service_handle_list
	
	for i in range(0, fuzz_iteration):
		service_handle = choice(service_handle_list)

def fuzz_sdp_service_search(bt_addr, sock, logger):
	global fuzz_iteration
	global current_tranid
	for i in range(0, fuzz_iteration):
		current_tranid = (current_tranid + 1) % 0x10000
		param_dict, strategy, packet = generate_sdp_service_search_packet_for_fuzzing(current_tranid=current_tranid)
		sock, packet_info, response = send_sdp_packet(bt_addr=bt_addr, sock=sock, packet=packet, packet_type=0x02, process_resp=True)
		if packet_info != "":
			packet_info["param_dict"] = param_dict
			packet_info["strategy"] = strategy
			logger["packet"].append(packet_info)

def sdp_fuzzing(bt_addr, test_info):
	global current_tranid
	global packet_count
	global crash_count
	with open('sdp_log_{}.wfl'.format(test_info["starting_time"][11:19].replace(':',"",2)), 'w', encoding="utf-8") as f:
		logger = OrderedDict()
		logger.update(test_info)
		logger["packet"] = []
		print("Start Fuzzing... Please hit Ctrl + C to finish...")
		try:
			#while (1):
			# print("[+] Tested %d packets" % (packet_count))	
			# if(len(logger['packet']) > 200000):
			# 	del logger['packet'][:100000]
			# sock = bluetooth.BluetoothSocket(bluetooth.L2CAP)
			# fuzz_sdp_service_search(bt_addr=bt_addr, sock=sock, logger=logger)
			send_test_packet(bt_addr=bt_addr, logger=logger)
				
		except Exception as e:
			print("[!] Error Message :", e)
			print(traceback.format_exc())
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
			print(logger)
			json.dump(logger, f, indent="\t")
			
	
