import os
import subprocess
from clean_response import clean_response, process_test_results, process_packet_results
import json 
import datetime
import sys 
import argparse
import logging
import subprocess
from colorlog import ColoredFormatter
from llm_gen_tests import get_tests 
from validate_with_tshark import *
from combine_dats_to_pcap import generate_pcap
import math 
from validate_with_tshark import *

module_names = {
    "Ethernet"  : ("_ETHERNET_FRAME"),
    "IP"   : ("_IPV4_HEADER"),
    "IPV4" : ("_IPV4_HEADER"),
    "IPV6" : ("_IPV6_HEADER"),
    "VXLAN": ("_VXLAN_HEADER"),
    "TCP"  : ("_TCP_HEADER"),
    "ICMP" : ("_ICMP_DATAGRAM"),
    "UDP"  : ("_UDP_Header"),
    "TPKT" : ("_TPKT_HEADER"),
    "ARP"  : ("_ARP_HEADER"),
    "IGMP" : ("_IGMP_HEADER"),
    "NTP"  : ("_NTP_HEADER"),
    "PPP"  : ("_PPP_HEADER"),
    "SIP"  : ("_SIP_HEADER"),
    "RTP"  : ("_RTP_HEADER"),
    "GRE"  : ("_GRE_HEADER"),
    "BGP"  : ("_BGP_HEADER"),
    "GHCP" : ("_DCHP_HEADER"),
    "DCCP" : ("_DCCP_HEADER"),
    "DHCP" : ("_DHCP_HEADER"),
    "NBNS" : ("_NBNS_HEADER"),
    "RIP"  : ("_RIP_HEADER"),
    "OSPF" : ("_OSPF_HEADER"),
    "EAP"  : ("_EAP_HEADER"),
    "SNMP" : ("_SNMP_HEADER"),
    "TFTP" : ("_TFTP_HEADER"),
    "Netlink" : ("_NETLINK_HEADER")
}



def logger_setup():
    LOG_LEVEL = logging.DEBUG
    LOGFORMAT = "  %(log_color)s%(levelname)-8s%(reset)s | %(log_color)s%(message)s%(reset)s"
    formatter = ColoredFormatter(LOGFORMAT)
    logging.root.setLevel(LOG_LEVEL)
    stream = logging.StreamHandler()
    stream.setLevel(LOG_LEVEL)
    stream.setFormatter(formatter)
    log = logging.getLogger('pythonConfig')
    log.setLevel(LOG_LEVEL)
    log.addHandler(stream)
    return log

def z3_gen(args):
    spec = ""
    out = os.path.join(args.out, "z3")
    out = os.path.abspath(out)
    if not os.path.exists(out):
        os.mkdir(out)

    filename = str(os.path.basename(args.spec))
    filename = filename.split('.3d')[0]  
    spec = args.spec  
   
    call = f"bash everparse/everparse.sh {spec} --no_batch --z3_test {filename}.{module_names[args.protocol]} --z3_branch_depth {args.z3_branch_depth} --z3_witnesses {args.z3_witnesses}  --odir {out}"
    print(call)
    sp = subprocess.Popen(call, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    _, err = sp.communicate()
    if sp.returncode != 0:
        raise Exception(f'Subprocess {call} failed with error code: {sp.returncode} and error message: {err}')
    
    # list number of files in the directory
    num_files = len([f for f in os.listdir(out) if os.path.isfile(os.path.join(out, f))])
    if num_files <= 200:
        print(f"Error: Not enough witnesses generated. Only {num_files} were generated")
        #deleted the dir
        call = f"rm -rf {out}/*"
        subprocess.run(call, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        num_witnesses =  math.ceil(200 / (num_files))
       
        
        call = f"bash everparse/everparse.sh {spec} --no_batch --z3_test {filename}.{module_names[args.protocol]} --z3_branch_depth {args.z3_branch_depth} --z3_witnesses {num_witnesses}  --odir {out}"
        print(call)
        sp = subprocess.Popen(call, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        _, err = sp.communicate()
        if sp.returncode != 0:
            raise Exception(f'Subprocess {call} failed with error code: {sp.returncode} and error message: {err}')
        
    
    # generate pcap from witnesses
    pcap_file_path = os.path.join(out, f"{filename}.z3.pcap")
    pcap_file_path = os.path.abspath(pcap_file_path)
    generate_pcap(out, args.protocol, pcap_file_path)
    results, _  = validate_and_coverage(pcap_file_path, str(args.protocol).lower(), False, True)
    print(results)
    
    
    with open(f"{out}/z3_packet_labels.json", 'w') as f:
        json.dump(results, f)      
    
    stats = f"Branch depth {args.z3_branch_depth}, Witnesses {num_witnesses}"
    with open(f"{out}/run_stats.txt", 'w') as f:
        json.dump(stats, f)
    
    return pcap_file_path
 

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--protocol', type=str, help='Protocol to test [ipv4|ipv6|tcp|udp|icmp|vxlan]', required=True)
    parser.add_argument('--out', type=str, help='output directory', required=False)
    parser.add_argument('--z3_branch_depth', type=int, help='Z3 branch depth', required=False, default=0)
    parser.add_argument('--z3_witnesses', type=int, help='z3 number of witnesses to generate', required=False, default=10)
    parser.add_argument('--rfc', type=str, help='/absolute/or/relative/path/to/rfc file', required=False)
    parser.add_argument('--spec', type=str, required=True, help='spec to use for Z3 test generation')

    args = parser.parse_args()
    log = logger_setup()
    
    os.mkdir(args.out)

    ## Generate tests using a spec
    print("*"*50)
    log.info("Test Case Generation: generating packets using z3...")
    z3_pcap_file_path = z3_gen(args) 
   