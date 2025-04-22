import sys, os, subprocess
import json, datetime
import bluetooth
from l2cap_fuzzer import *
from random import *
from collections import OrderedDict
from sdp_packet import *
from sdp_util import *
import traceback
from config import ConfigManager
current_tranid = 0x0001
packet_count = 0
crash_count = 0
service_handle_list = []
fuzz_iteration = 5000
continuation_state_list = []
def send_sdp_packet(bt_addr, sock, packet, packet_type, process_resp=False):
	global packet_count, crash_count
	packet_count += 1
	packet_info = ""
	response = b'\x00'
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
		packet_info["sended?"] = "y"	
		
		if process_resp:
			response = sock.recv(4096)
			packet_info["response_data"] = response.hex()
		# else:
		sock = bluetooth.BluetoothSocket(bluetooth.L2CAP)
		sock.connect((bt_addr, 1))
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
			packet_info = {}
			packet_info["no"] = packet_count
			packet_info["protocol"] = "SDP"
			packet_info["sent_time"] = str(datetime.now())
			packet_info["packet_type"] = packet_type
			packet_info["raw_packet"] = packet.hex()
			packet_info["sended?"] = "n"			
			packet_info["crash"] = "y"
			packet_info["DoS"] = "y"
			packet_info["crash_info"] = str(e)
	

	return sock, packet_info, response

def send_test_packet(bt_addr,logger):
	global current_tranid
	service_uuids = [ASSIGNED_SERVICE_UUID["Public Browse Group"]]
	param_dict, sdp_packet = build_sdp_service_search_attr_request(current_tranid, service_uuids, 0xFFFF, [{"attribute_id":(0x0001 << 16) | 0xFFFF, "isRange": True}])
	current_tranid += 1
	
	sock = bluetooth.BluetoothSocket(bluetooth.L2CAP)
	sock.connect((bt_addr, 1))
	sock, packet_info, response = send_sdp_packet(bt_addr, sock, sdp_packet, 0x02, True)
	
	if packet_info != "":
		packet_info["params"] = param_dict
		log_packet(logger, packet_info)



	resp_data = parse_sdp_response(response)
	if resp_data["continuation_state"] != b"\x00":
		print(f"Continuation state: {resp_data["continuation_state"]}")
		param_dict, sdp_packet = build_sdp_service_search_attr_request(current_tranid, service_uuids, 0xFFFF, [{"attribute_id":(0x0001 << 16) | 0xFFFF, "isRange": True}], resp_data["continuation_state"])
		sock, packet_info, response = send_sdp_packet(bt_addr, sock, sdp_packet, 0x02, True)
		
		if packet_info != "":
			packet_info["param_dict"] = param_dict
			log_packet(logger, packet_info)


def send_initial_sdp_service_search(bt_add, sock, logger):
	print("[+] Sending initial SDP service search to get all service handles...")
	global current_tranid
	global service_handle_list
	for key in ASSIGNED_SERVICE_UUID.keys():
		param_dict, packet = build_sdp_search_request(current_tranid, 0xFF, [ASSIGNED_SERVICE_UUID[key]])
		sock, packet_info, response = send_sdp_packet(bt_addr=bt_add, sock=sock, packet=packet, packet_type=0x02, process_resp=True)
		if packet_info != "":
			packet_info["params"] = param_dict
			log_packet(logger, packet_info)
			if response != b'\x00':
				resp = parse_sdp_response(response)
				if resp["handle_list"] is not None:
					service_handle_list.extend(resp["handle_list"])
	if len(service_handle_list) == 0: #in case no service handle
		srh = int.from_bytes(b'\x10\x01', byteorder="big")

		service_handle_list.append(struct.pack(">I", srh))
	service_handle_list = list(set(service_handle_list))
	current_tranid = (current_tranid + 1) % 0x10000

def send_initial_sdp_search_attr_req(bt_addr, sock, logger):
	print("[+] Getting continuation states for service search attribute requests...")
	global current_tranid	
	current_tranid = (current_tranid + 1) % 0x10000
	attr_list = generate_fixed_attribute_list1()
	uuid_list = generate_fixed_uuid_list1()
	max_attr_byte_count = 0xFF #for mutating known continuation state, we will fix the max attr byte
	param_dict, packet = build_sdp_service_search_attr_request(tid=current_tranid, uuid_list=uuid_list, max_attr_byte_count=max_attr_byte_count, attribute_list=attr_list, continuation_state=b'\x00', to_fuzz=False)
	sock, packet_info, response = send_sdp_packet(bt_addr=bt_addr, sock=sock, packet=packet, packet_type=0x06, process_resp=True)
	if packet_info != "":
		
		packet_info["params"] = param_dict
		packet_info["strategy"] = "Getting Continuation States"
		log_packet(logger, packet_info)
		resp = parse_sdp_response(response)
		while resp["continuation_state"] != b'\x00':
			continuation_state_list.append(resp["continuation_state"])
			current_tranid = (current_tranid + 1) % 0x10000
			param_dict, packet = build_sdp_service_search_attr_request(tid=current_tranid, uuid_list=uuid_list, max_attr_byte_count=max_attr_byte_count, attribute_list=attr_list, continuation_state=resp["continuation_state"], to_fuzz=False)
			sock, packet_info, response = send_sdp_packet(bt_addr=bt_addr, sock=sock, packet=packet, packet_type=0x06, process_resp=True)
			resp = parse_sdp_response(response)
	print(f"[+] Valid Continuation States: {continuation_state_list}")
 
def fuzz_sdp_full_garbage(bt_addr, sock, logger):
	print("[+] Fuzzing SDP (Full Garbage Packets)")
	global current_tranid
	global fuzz_iteration
	
	for _ in range(0, fuzz_iteration):
		current_tranid = (current_tranid + 1) % 0x10000
		pdu_id = randrange(0x01, 0x08)
		param_dict, strategy, packet = generate_garbage_sdp_packet_for_fuzzing(current_tranid=current_tranid, pdu_id=pdu_id)
		sock, packet_info, response = send_sdp_packet(bt_addr=bt_addr, sock=sock, packet=packet, packet_type=pdu_id, process_resp=False)
		if packet_info != "":
			packet_info["params"] = param_dict
			packet_info["strategy"] = strategy
			log_packet(logger, packet_info)



def fuzz_sdp_service_search_attr_garbage_list(bt_addr, sock, logger):
	print("[+] Fuzzing SDP Service Search Attributes (Add garbage to lists)")
	global current_tranid
	global fuzz_iteration
	for _ in range(0, fuzz_iteration):
		current_tranid = (current_tranid + 1) % 0x10000
		attr_list = generate_fixed_attribute_list1()
		uuid_list = generate_fixed_uuid_list()
		max_attr_byte_count = randrange(0x07, 0x10000)
		param_dict, packet = build_sdp_service_search_attr_request(tid=current_tranid, uuid_list=uuid_list, max_attr_byte_count=max_attr_byte_count, attribute_list=attr_list, continuation_state=b'\x00', to_fuzz=True)
		sock, packet_info, response = send_sdp_packet(bt_addr=bt_addr, sock=sock, packet=packet, packet_type=0x06, process_resp=True)
		if packet_info != "":
			
			packet_info["params"] = param_dict
			packet_info["strategy"] = "Add garbage to UUID/Attribute List"
			log_packet(logger, packet_info)
			resp = parse_sdp_response(response)
			while resp["continuation_state"] != b'\x00':
				current_tranid = (current_tranid + 1) % 0x10000
				param_dict, packet = build_sdp_service_search_attr_request(tid=current_tranid, uuid_list=uuid_list, max_attr_byte_count=max_attr_byte_count, attribute_list=attr_list, continuation_state=resp["continuation_state"], to_fuzz=False)
				sock, packet_info, response = send_sdp_packet(bt_addr=bt_addr, sock=sock, packet=packet, packet_type=0x06, process_resp=True)
				if packet_info != "":
					
					packet_info["params"] = param_dict
					packet_info["strategy"] = "Add garbage to UUID/Attribute List"
					log_packet(logger, packet_info)
				resp = parse_sdp_response(response)
		else:
			print("Nothing for Service Search Attributes?")

def fuzz_sdp_service_search_attr_mutate_continuation_state_length(bt_addr, sock, logger): 
	print("[+] Fuzzing SDP Service Search Attributes (Mutate length of known continuation states)")
	global current_tranid
	current_tranid = (current_tranid + 1) % 0x10000

	max_attr_byte_count = 0xFF #for mutating known continuation state, we will fix the max attr byte
	for _ in range(0, fuzz_iteration):
		attr_list = generate_fixed_attribute_list1()
		uuid_list = generate_fixed_uuid_list1()
		old_continuation_state = choice(continuation_state_list)
		content_length = len(old_continuation_state) - 1
		new_content_length = content_length + randrange(1,0x10)
		continuation_state = struct.pack(">B", new_content_length) + old_continuation_state[1:]
		param_dict, packet = build_sdp_service_search_attr_request(tid=current_tranid, uuid_list=uuid_list, max_attr_byte_count=max_attr_byte_count, attribute_list=attr_list, continuation_state=continuation_state, to_fuzz=False)
		sock, packet_info, response = send_sdp_packet(bt_addr=bt_addr, sock=sock, packet=packet, packet_type=0x06, process_resp=True)
		if packet_info != "":
			
			packet_info["params"] = param_dict
			packet_info["strategy"] = "Mutate length known continuation state"
			log_packet(logger, packet_info)


			resp = parse_sdp_response(response)
			while resp["continuation_state"] != b'\x00':
				current_cont_state = resp["continuation_state"]
				current_cont_state = current_cont_state + generate_garbage_by_byte(byte_count=randrange(0x00, 0x10), add_length=False)
				param_dict, packet = build_sdp_service_search_attr_request(tid=current_tranid, uuid_list=uuid_list, max_attr_byte_count=max_attr_byte_count, attribute_list=attr_list, continuation_state=current_cont_state, to_fuzz=False)
				sock, packet_info, response = send_sdp_packet(bt_addr=bt_addr, sock=sock, packet=packet, packet_type=0x06, process_resp=True)
				if packet_info != "":
					
					packet_info["params"] = param_dict
					packet_info["strategy"] = "Mutate length known continuation state"
					log_packet(logger, packet_info)
				resp = parse_sdp_response(response)
		else:
			print("Nothing for Service Search Attributes?")	


def fuzz_sdp_service_search_attr_mutate_continuation_state(bt_addr, sock, logger):
	print("[+] Fuzzing SDP Service Search Attributes (Mutate known continuation states)")
	global current_tranid
	global fuzz_iteration
	current_tranid = (current_tranid + 1) % 0x10000

	attr_list = generate_fixed_attribute_list1()
	uuid_list = generate_fixed_uuid_list1()

	max_attr_byte_count = 0xFF #for mutating known continuation state, we will fix the max attr byte
	for _ in range(0, fuzz_iteration):
		continuation_state = choice(continuation_state_list)
		content_length = len(continuation_state) - 1
		rand_index = randrange(1, content_length)
		continuation_state_lhs = continuation_state[0:rand_index]
	
		continuation_state_rhs = continuation_state[rand_index+1:]
		mutated_field = generate_garbage_by_byte(byte_count=1, add_length=False)
		continuation_state = continuation_state_lhs + mutated_field + continuation_state_rhs
		param_dict, packet = build_sdp_service_search_attr_request(tid=current_tranid, uuid_list=uuid_list, max_attr_byte_count=max_attr_byte_count, attribute_list=attr_list, continuation_state=continuation_state, to_fuzz=False)
		sock, packet_info, response = send_sdp_packet(bt_addr=bt_addr, sock=sock, packet=packet, packet_type=0x06, process_resp=True)
		if packet_info != "":
			
			packet_info["params"] = param_dict
			packet_info["strategy"] = "Mutate known continuation state"
			log_packet(logger, packet_info)


			resp = parse_sdp_response(response)
			while resp["continuation_state"] != b'\x00':
				current_cont_state = resp["continuation_state"]
				current_cont_state = current_cont_state + generate_garbage_by_byte(byte_count=randrange(0x00, 0x10), add_length=False)
				param_dict, packet = build_sdp_service_search_attr_request(tid=current_tranid, uuid_list=uuid_list, max_attr_byte_count=max_attr_byte_count, attribute_list=attr_list, continuation_state=current_cont_state, to_fuzz=False)
				sock, packet_info, response = send_sdp_packet(bt_addr=bt_addr, sock=sock, packet=packet, packet_type=0x06, process_resp=True)
				if packet_info != "":
					
					packet_info["params"] = param_dict
					packet_info["strategy"] = "Mutate known continuation state"
					log_packet(logger, packet_info)
				resp = parse_sdp_response(response)
		else:
			print("Nothing for Service Search Attributes?")


def fuzz_sdp_service_search_attr_garbage_continuation_state(bt_addr, sock, logger):
	print("[+] Fuzzing SDP Service Search Attributes (Add garbage to continuation state)")
	global current_tranid
	global fuzz_iteration
	current_tranid = (current_tranid + 1) % 0x10000
	for _ in range(0, fuzz_iteration):
		attr_list = generate_fixed_attribute_list1()
		uuid_list = generate_fixed_uuid_list()
		max_attr_byte_count = randrange(0x07, 0x10000)
		garbage_value = generate_garbage_by_byte(byte_count=randrange(0x02, 0x10), add_length=True) #generate_garbage(add_length=True)
		param_dict, packet = build_sdp_service_search_attr_request(tid=current_tranid, uuid_list=uuid_list, max_attr_byte_count=max_attr_byte_count, attribute_list=attr_list, continuation_state=garbage_value, to_fuzz=False)
		sock, packet_info, response = send_sdp_packet(bt_addr=bt_addr, sock=sock, packet=packet, packet_type=0x06, process_resp=True)
		if packet_info != "":
			
			packet_info["params"] = param_dict
			packet_info["strategy"] = "Add garbage to continuation state"
			log_packet(logger, packet_info)


			resp = parse_sdp_response(response)
			while resp["continuation_state"] != b'\x00':
				current_cont_state = resp["continuation_state"]
				current_cont_state = current_cont_state + generate_garbage_by_byte(byte_count=randrange(0x00, 0x10), add_length=False)
				param_dict, packet = build_sdp_service_search_attr_request(tid=current_tranid, uuid_list=uuid_list, max_attr_byte_count=max_attr_byte_count, attribute_list=attr_list, continuation_state=current_cont_state, to_fuzz=False)
				sock, packet_info, response = send_sdp_packet(bt_addr=bt_addr, sock=sock, packet=packet, packet_type=0x06, process_resp=True)
				if packet_info != "":
					
					packet_info["params"] = param_dict
					packet_info["strategy"] = "Add garbage to continuation state"
					log_packet(logger, packet_info)
				resp = parse_sdp_response(response)
		else:
			print("Nothing for Service Search Attributes?")


def fuzz_sdp_service_attr_garbage_list(bt_addr, sock, logger):
	print("[+] Fuzzing SDP Service Attributes (Add garbage to lists)")
	global fuzz_iteration
	global current_tranid
	global service_handle_list
	for _ in range(0, fuzz_iteration):
		service_handle = choice(service_handle_list)
		current_tranid = (current_tranid + 1) % 0x10000
		attr_list = generate_fixed_attribute_list1()
		param_dict, packet = build_sdp_service_attr_request(tid=current_tranid, service_record_handle=service_handle, max_attr_byte_count=randrange(0x07, 0x10000), attribute_list=attr_list, continuation_state=b'\x00', to_fuzz=True)
		sock, packet_info, _ = send_sdp_packet(bt_addr=bt_addr, sock=sock, packet=packet, packet_type=0x04, process_resp=False)
		if packet_info != "":
			
			packet_info["param_dict"] = param_dict
			packet_info["strategy"] = "Add garbage to UUID/Attribute List"
			log_packet(logger, packet_info)
		else:
			print("Nothing for Service Attributes?")

def fuzz_sdp_service_attr_garbage_continuation_state(bt_addr, sock, logger):
	print("[+] Fuzzing SDP Service Attributes (Add garbage to continuation state)")
	global fuzz_iteration
	global current_tranid
	global service_handle_list
	current_tranid = (current_tranid + 1) % 0x10000
	for _ in range(0, fuzz_iteration):
		service_handle = choice(service_handle_list)
		attr_list = generate_fixed_attribute_list1()
		garbage_value = generate_garbage_by_byte(byte_count=randrange(0x02, 0x10), add_length=True)
		param_dict, packet = build_sdp_service_attr_request(tid=current_tranid, service_record_handle=service_handle, max_attr_byte_count=randrange(0x07, 0x10000), attribute_list=attr_list, continuation_state=garbage_value, to_fuzz=False)
		sock, packet_info, _ = send_sdp_packet(bt_addr=bt_addr, sock=sock, packet=packet, packet_type=0x04, process_resp=False)
		if packet_info != "":
			
			packet_info["param_dict"] = param_dict
			packet_info["strategy"] = "Add garbage to continuation state"
			log_packet(logger, packet_info)
		else:
			print("Nothing for Service Attributes?")

def fuzz_sdp_service_search_garbage_list(bt_addr, sock, logger):
	print("[+] Fuzzing SDP Service Search (Add garbage to lists)")
	global fuzz_iteration
	global current_tranid
	for _ in range(0, fuzz_iteration):
		current_tranid = (current_tranid+1) % 0x10000
		uuid_list = generate_fixed_uuid_list()
		param_dict, packet = build_sdp_search_request(tid=current_tranid, max_record=randrange(0x01, 0x10000), uuid_list=uuid_list, continuation_state=b'\x00', to_fuzz=True)
		sock, packet_info, _ = send_sdp_packet(bt_addr=bt_addr, sock=sock, packet=packet, packet_type=0x02, process_resp=False)
		if packet_info != "":
			
			packet_info["param_dict"] = param_dict
			packet_info["strategy"] = "Add garbage to UUID/Attribute List"
			log_packet(logger, packet_info)
		else:
			print("Nothing for Service Search?")

def fuzz_sdp_service_search_garbage_continuation_state(bt_addr, sock, logger):
	print("[+] Fuzzing SDP Service Search (Add garbage to continuation state)")
	global fuzz_iteration
	global current_tranid
	current_tranid = (current_tranid+1) % 0x10000
	for _ in range(0, fuzz_iteration):
		uuid_list = generate_fixed_uuid_list()
		garbage_value = generate_garbage_by_byte(byte_count=randrange(0x02, 0x10), add_length=True)
		param_dict, packet = build_sdp_search_request(tid=current_tranid, max_record=randrange(0x01, 0x10000), uuid_list=uuid_list, continuation_state=garbage_value, to_fuzz=False)
		sock, packet_info, _ = send_sdp_packet(bt_addr=bt_addr, sock=sock, packet=packet, packet_type=0x02, process_resp=False)
		if packet_info != "":
			
			packet_info["param_dict"] = param_dict
			packet_info["strategy"] = "Add garbage to continuation state"
			log_packet(logger, packet_info)
		else:
			print("Nothing for Service Search?")



def sdp_fuzzing(bt_addr, test_info):
	global current_tranid
	global packet_count
	global crash_count
	global fuzz_iteration
	with open('sdp_log_{}.wfl'.format(test_info["starting_time"]), 'w', encoding="utf-8") as f:
		logger = OrderedDict()
		logger.update(test_info)
		logger["packet"] = []
		fuzz_iteration = ConfigManager.get_fuzz_iteration()

		print("Start Fuzzing... Please hit Ctrl + C to finish...")
		try:
			sock = bluetooth.BluetoothSocket(bluetooth.L2CAP)
			sock.connect((bt_addr, 1))
			send_initial_sdp_service_search(bt_add=bt_addr, sock=sock, logger=logger)
			send_initial_sdp_search_attr_req(bt_addr=bt_addr, sock=sock, logger=logger)
			while (1):
				print("[+] Tested %d packets" % (packet_count))	
				if(len(logger['packet']) > 200000):
					del logger['packet'][:100000]
				
				if ConfigManager.get_random_fuzzing():
					fuzz_sdp_full_garbage(bt_addr=bt_addr, sock=sock, logger=logger)
				
				print('[+] FUZZING CONTINUATION STATES')
				if len(continuation_state_list) > 0:
					fuzz_sdp_service_search_attr_mutate_continuation_state(bt_addr=bt_addr, sock=sock, logger=logger)
					fuzz_sdp_service_search_attr_mutate_continuation_state_length(bt_addr=bt_addr, sock=sock, logger=logger)

				fuzz_sdp_service_search_garbage_continuation_state(bt_addr=bt_addr, sock=sock, logger=logger)
				fuzz_sdp_service_attr_garbage_continuation_state(bt_addr=bt_addr, sock=sock, logger=logger)
				fuzz_sdp_service_search_attr_garbage_continuation_state(bt_addr=bt_addr, sock=sock, logger=logger)

				if ConfigManager.get_to_fuzz_garbage_list():
					print('[+] FUZZING GARBAGE LISTS')
					fuzz_sdp_service_search_garbage_list(bt_addr=bt_addr, sock=sock, logger=logger)
		
					fuzz_sdp_service_attr_garbage_list(bt_addr=bt_addr, sock=sock, logger=logger)
		
					fuzz_sdp_service_search_attr_garbage_list(bt_addr=bt_addr, sock=sock, logger=logger)

				#send_test_packet(bt_addr=bt_addr, logger=logger)
			# 	#break
				
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
			#print(logger)
			json.dump(logger, f, indent="\t")
			
	
