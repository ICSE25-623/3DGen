#!/usr/bin/env python3

import os
import tempfile
import argparse
import pyshark
from scapy.all import *

"""
This script combines a set of .dat files into a single tshark (wireshark) pcap file.
As input, it takes:
1) The path to a folder containing the .dat files
2) A tshark dissector name, i.e., the protocol corresponding to the .dat files. Thus, 
   the set of .dat files have to be of a single protocol.
3) The path (including the filename) to the generated .pcap file

A .pcap file usually does not contain a single protocol. Instead, it contains packets 
that consist of multiple layers such as Ethernet > IP > TCP > HTTP. We speak of Ethernet 
in this example as the root layer and HTTP as the leaf layer. Alternatively, one might 
call Ethernet, IP, TCP the encapsulation layer and HTTP the payload layer. The .dat files, 
on the other hand, are the raw bytes of a single layer. For tshark to dissect some layer, 
it typically expects the encapsulation and payload layers to be present. However, we do 
not want to add knowledge to this script about the encapsulation layers. Thus, we rely 
on tshark's export pdu feature, which is a special, generic encapsulation layer that 
contains the name of the payload layer. Unfortunately, in some cases, we still have to 
add encapsulation and leaf layers when we assemble the packet from the .dat files because 
of inconsistencies with tshark's dissectors. To assemble encapsulation and leaf layers, 
we use text2pcap features and scapy.

As output, it generates a single .pcap file with N assembled packets where N is the number 
of .dat files. Each packet has a tshark frame comment that corresponds to the .dat file 
name. The order in which the packets appear in the .pcap file is undefined.

Why do we combine .dat files into a single pcap file instead of one .pcap file per .dat file?
a) Diagnosing malformed packets with tshark (wireshark) is easier with a single pcap file. 
   Otherwise, one has to constantly switch between different .pcap files.
b) tshark supports packet flows such as TCP handshakes, retransmissions. However, all the 
   packets of that handshake have to be in one .pcap file.

This script expects text2pcap, editcap, and mergecap, as well as od to be installed on the 
system. These are part of the wireshark package except for od, which is part of the coreutils 
package. DO NOT replace od with hexdump, as hexdump has subtle differences in its output that 
can interfere with text2pcap. Moreover, text2pcap specifically mentions od in its documentation.
"""

## 1-arity identity function.
_ = lambda x: x

tshark_instructions = {
    ## protocol name: (tshark argument, scapy layer constructor if needed)
    ## "-l 252" would no longer be necessary with https://github.com/wireshark/wireshark/commit/339d6d4aba6f51f32c9483ea4dab5790b713d247.
    "eth"  : ("-F pcap",                  lambda layer : Ether(layer) / IP() / ICMP()),
    "ipv4" : ("-F pcap -l 252 -P ip",     lambda layer : IP(layer) / Raw(load=bytes(IP(layer).len - (IP(layer).ihl * 4)))),
    "ipv6" : ("-F pcap -l 252 -P ipv6",   lambda layer : IPv6(layer) / Raw(load=bytes(IPv6(layer).plen))),
    "vxlan": ("-F pcap -l 252 -P vxlan",  lambda layer : VXLAN(layer) / Ether() / IP() / ICMP()),
    "tcp"  : ("-F pcap -l 252 -P tcp",    lambda layer : TCP(layer) / Raw(load=bytes(TCP(layer).dataofs * 4))),
    "udp"  : ("-F pcap -l 252 -P udp",    lambda layer : UDP(layer) / Raw(bytes(UDP(layer).len - 8))),
    "icmp" : ("-F pcap -l 252 -P icmp",   _),
    "tpkt" : ("-F pcap -l 252 -P tpkt",   _),
    "arp"  : ("-F pcap -l 252 -P arp",    _),
    "igmp" : ("-F pcap -l 252 -P igmp",   _),
    "ntp"  : ("-F pcap -l 252 -P ntp",    _),
    "ppp"  : ("-F pcap -l 252 -P ppp",    _),
    "sip"  : ("-F pcap -l 252 -P sip",    _),
    "rtp"  : ("-F pcap -l 252 -P rtp",    _),
    "gre"  : ("-F pcap -l 252 -P gre",    _),
    "bgp"  : ("-F pcap -l 252 -P bgp",    _),
    "dhcp" : ("-F pcap -l 252 -P dhcp",   _),
    "dccp" : ("-F pcap -l 252 -P dccp",   _),
    "nbns" : ("-F pcap -l 252 -P nbns",   _),
    "rip"  : ("-F pcap -l 252 -P rip",    _),
    "ospf" : ("-F pcap -l 252 -P ospf",   _),
    "eap"  : ("-F pcap -l 252 -P eap",    _),
    "snmp" : ("-F pcap -l 252 -P snmp",   _),
    "tftp" : ("-u 69,69",                 _),
}

def generate_pcap(dat_folder_path, protocol, pcap_file_path):
    if not os.path.isabs(pcap_file_path):
        print(f"The pcap_file_path has to be absolute: {pcap_file_path}")
        sys.exit(-1)

    # if pcap file does not exist, create it
    if not os.path.exists(pcap_file_path):
        open(pcap_file_path, 'w').close()
        
        
    ## Ensure that the tshark dissector name is lowercase.
    protocol = protocol.lower()
    
    # 1) Assemble the packets from the .dat files with scape
    # 2) Generate a .pcap file for each .dat file with text2pcap
    # 3) Set the frame comment of the packet in the .pcap file to the .dat file name with editcap 
    # 4) Merge the .pcap files into a single .pcap file with mergecap
    # 5) Assert that the .pcap files contain N packets where N is the number of .dat files.
    # 6) Validate that every packet in the .pcap file has a comment.

    # 1) Generate a .pcap file for each .dat file
    with tempfile.TemporaryDirectory() as temp_dir:
        ## Make sure the gcov instrumented tshark finds its .gcda files.
        os.environ['GCOV_PREFIX'] = temp_dir
        os.environ['GCOV_PREFIX_STRIP'] = '5'

        N = 0
        ## Sort input files lexicopgraphically to ensure some order in the .pcap file.
        for dat_file_name in sorted(os.listdir(dat_folder_path)):
            # Omit files not ending in .dat
            if not dat_file_name.endswith(".dat"):
                continue

            dat_file_path = os.path.join(dat_folder_path, dat_file_name)

            # 1a) Assemble the packets from the .dat files with scapy
            ### Read a .dat file into pkt_layer.
            with open(dat_file_path, 'rb') as file:
                without_nested_layers = file.read()

            ### Compose a network packet from the pkt_layer by appending nested protocol
            ### layers and write it to the pcap file.  This might fail for negative (NEG) packets, in which case we skip assembling additional layers.
            try:
                pkt = tshark_instructions[protocol][1](without_nested_layers)
                with_nested_layers = bytes(pkt)
            except Exception as e:
                print(e)
                print(f"Skipping the assembly of nested layers due to malformed input {dat_file_path}.")
                ## Skipping assembly of nested layers if input layer in .dat file is malformed beyond scapy's parsing capabilities. This is useful for negative (NEG) packets.
                with_nested_layers = without_nested_layers

            ## 1b) Write (hence 'wb') the bytes to a file with the name of the dat file in the temp directory.
            ## It is tempting to drop text2pcap and generate the pcap file with scapy.  However, scapy does not support text2pcap's export pdu option.
            ## We would have to also assemble the outer layers up to the ethernet frame.  More minor but also relevant, scapy doesn't seem to support
            ## comments that we use to associate the pcap frames with the Everparse .dat files.
            dat_temp_file = os.path.join(temp_dir, dat_file_name)
            with open(dat_temp_file, 'wb') as file:
                file.write(with_nested_layers)

            # 2) Generate a .pcap file for each .dat file with text2pcap.
            pcap_temp_path = os.path.join(temp_dir, dat_file_name + ".pcap")
            call = (f"od -Ax -tx1 -v {dat_temp_file} | text2pcap -q {tshark_instructions[protocol][0]} - {pcap_temp_path}")
            sp = subprocess.Popen(call, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=temp_dir)
            _, err = sp.communicate()
            if sp.returncode != 0:
                raise Exception(f'Subprocess {call} failed with error code: {sp.returncode} and error message: {err}') 

            ## 3) Set the frame comment of the packet in the .pcap file to the .dat file name with editcap.
            ## editcap is one-based, so the first frame is frame #1.
            call = (f"editcap -a \"1:{dat_file_name}\" {pcap_temp_path} {pcap_temp_path}")
            sp = subprocess.Popen(call, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=temp_dir)
            _, err = sp.communicate()
            if sp.returncode != 0:
                raise Exception(f'Subprocess {call} failed with error code: {sp.returncode} and error message: {err}')
            
            ## 5) Assert that the .pcap files contain N packets where N is the number of .dat files (continues below).
            N += 1

        # 4) Merge the .pcap files into a single .pcap file with mergecap.
        call = (f"mergecap -w {pcap_file_path} {temp_dir}/*.pcap")
        sp = subprocess.Popen(call, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=temp_dir)
        _, err = sp.communicate()
        if sp.returncode != 0:
            raise Exception(f'Subprocess {call} failed with error code: {sp.returncode} and error message: {err}') 

        # 6) Validate that every packet in the .pcap file has a comment.
        cap = pyshark.FileCapture(input_file=pcap_file_path)
        for packet in cap:
            N -= 1
            assert hasattr(packet, 'frame_info') and hasattr(packet.frame_info, 'frame_comment')
        cap.close()

        # 5) Assert that the .pcap files contain N packets where N is the number of .dat files.
        assert N == 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--protocol', type=str, help='Protocol to test [ipv4|ipv6|tcp|udp|icmp|vxlan|...]', required=True)
    parser.add_argument('--input', type=str, help='/absolute/or/relative/path/to/folder/with/.dat files', required=True)
    parser.add_argument('--output', type=str, help='/absolute/path/to/generated/.pcap file', required=True)
    args = parser.parse_args()

    generate_pcap(args.input, args.protocol, args.output)

if __name__ == "__main__":
    main()