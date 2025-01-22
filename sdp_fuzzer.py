import sys, os, subprocess
import json, datetime

from statemachine import StateMachine, State
from scapy.all import *
from scapy.packet import Packet
from random import *
from collections import OrderedDict

def sdp_fuzzing(bt_addr, test_info):
    print("SDP fuzzing WIP")