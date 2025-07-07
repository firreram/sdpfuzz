# L2Fuzz + SDPFuzz
Original Repo: https://github.com/haramel/l2fuzz

A stateful fuzzer to detect vulnerabilities in Bluetooth BR/EDR Logical Link Control and Adaptation Protocol (L2CAP) layer.

SDPFuzz is an extension that builds on top of L2Fuzz to detect vulnerabilites in Service Discovery Protocol

## Prerequisites

L2Fuzz uses python3.6.9 and scapy 2.4.4. Also, it uses Bluetooth Dongle.

SDPFuzz is tested on Kali 2024.4 and Ubuntu 24.04. The Bluetooth Dongle used is a TP-Link Bluetooth dongle.

```
sudo apt-get install python3-pip
pip3 install scapy==2.4.4
sudo apt-get install libbluetooth-dev
sudo pip3 install git+https://github.com/pybluez/pybluez.git#egg=pybluez
pip3 install python-statemachine
pip3 install ouilookup
```

## Running the tests

1. move to L2Fuzz folder.
2. run the following command 
```
sudo venv/bin/python3.10 l2fuzz.py
```
3. Choose target device.
```
Reset Bluetooth...
Performing classic bluetooth inquiry scan...

	Target Bluetooth Device List
	[No.]	[BT address]		  [Device name]		[Device Class]	  	[OUI]
	00.	AA:BB:CC:DD:EE:FF	  DESKTOP       	Desktop   	      	Vendor A
	01.	11:22:33:44:55:66	  Smartphone    	Smartphone	      	Vendor B
	Found 2 devices

Choose Fuzzer : 
```
4. Choose either L2CAP fuzzing or SDP fuzzing

5. Fuzz testing start.

### End test

```
Ctrl + C
```

### Log file

The log file will be generated after the fuzz testing in L2Fuzz folder.
