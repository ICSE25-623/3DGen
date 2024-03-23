#!/usr/bin/env python3

import os
import tempfile
import shutil
import argparse
import subprocess
import pyshark


class KeyDict(dict):
    def __missing__(self, key):
        return key
proto_alias = KeyDict({'ipv4': "ip"})


wireshark_expert_info = {
    0x00000000: ("None", 0), 
    0x00200000: ("Chat", 0), 
    0x00400000: ("Note", 0), 
    0x00600000: ("Warning", 10),
    0x00800000: ("Error", 100)
}


expert_info_color = {
    "None": "\033[0m",
    "Chat": "\033[32m",
    "Note": "\033[32m",
    "Warning": "\033[33m",
    "Error": "\033[31m",
}


def validate(pcap_file_path, protocol, debug = False, strict = False):

    ### Read the pcap file and print the icmp packet if any.
    cap = pyshark.FileCapture(input_file=pcap_file_path, override_prefs={"dccp.check_checksum": "FALSE", "udp.check_checksum": "FALSE", "udp.ignore_ipv6_zero_checksum": "FALSE"})
    ### Create a results json object with the packet name, whether it is valid or invalid, and the expert message if any.
    retVal  = 0
    results = {}
    for packet in cap:
        #print(packet)

        frame = packet.frame_info.frame_comment if "frame_comment" in packet.frame_info.field_names else packet.number
        if protocol in packet and (strict is False or "_WS.MALFORMED" not in packet) :
            if len(packet[protocol].field_names) > 0 :
                if "_ws_expert_severity" in packet[protocol].field_names :
                    ## The protocol has been found and tshark set some ws_expert_severity. If it's less than 0x00800000, it's not an error.
                    severity = int(packet[protocol]._ws_expert_severity)
                    results[frame] = (severity < 0x00800000, wireshark_expert_info[severity][0], packet[protocol]._ws_expert_message, wireshark_expert_info[severity][1])
                else :
                    ## The protocol has been found and tshark set no ws_expert_severity. Looks like a legit packet.
                    results[frame] = (True, "None", "", wireshark_expert_info[0][1])
            else :
                ## The protocol has been found but tshark found no fields.  This is fishy but not necessarily wrong.
                results[frame] = (False, "Warning", "Expected protocol found in packet but protocol layer has zero fields", wireshark_expert_info[0x00600000][1])
        else :
            ## The expected protocol has not been found. The packet must be completely malformed.
            results[frame] = (False, "Error", "Packet malformed to the point that the expected protocol is not found", wireshark_expert_info[0x00800000][1])

        out = results[frame]   
        
        retVal = max(retVal, 100 - out[3] if "NEG" in frame else out[3])

        print(f'{expert_info_color[out[1]]}input: {frame}, proto: {protocol}, valid: {out[0]}, severity: {out[1]}, message: {out[2]}\033[0m')
        if debug and out[0] == False:
            print(id, packet)
    
    cap.close()
    return results, retVal


## some dissector have non-matching names such as nbns (https://github.com/wireshark/wireshark/commit/c200f1e90bf75d5f15046d97657dafd4127ad278)
dissector_alias = KeyDict({'nbns': "nbt"})

def validate_and_coverage(pcap_file_path, protocol, debug = False, strict = False):
    protocol = proto_alias[protocol.lower()]

    with tempfile.TemporaryDirectory() as temp_dir:
        ## Make sure tshark writes gcov's (coverage) *.gcda files to temp_dir.
        os.environ['GCOV_PREFIX'] = temp_dir
        os.environ['GCOV_PREFIX_STRIP'] = '7'

        results, retVal = validate(pcap_file_path, protocol, debug, strict)

        dissector = dissector_alias[protocol]

        ## Copy .gcno and .o files from the wireshark/tshark installation to temp_dir for gcov to find them.
        shutil.copy2(f"/usr/include/wireshark/epan/dissectors/packet-{dissector}.c.o", temp_dir + f"/epan/dissectors/CMakeFiles/dissectors.dir/")
        shutil.copy2(f"/usr/include/wireshark/epan/dissectors/packet-{dissector}.c.gcno", temp_dir + f"/epan/dissectors/CMakeFiles/dissectors.dir/")
        
        ## With everything in place, create the gcov report.
        call = f"gcov -o {temp_dir}/epan/dissectors/CMakeFiles/dissectors.dir/packet-{dissector}.c.o /usr/include/wireshark/epan/dissectors/packet-{dissector}.c -f | grep -A1 \"packet-{dissector}.c'\""
        sp = subprocess.Popen(call, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=temp_dir)
        out, err = sp.communicate()
        if err:
            print(err.decode("utf-8"))
        if out:
            print(out.decode("utf-8"))

        return results, retVal


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--protocol', type=str, help='Protocol to test [ipv4|ipv6|tcp|udp|icmp|vxlan|...]', required=True)
    parser.add_argument('--input', type=str, help='/absolute/or/relative/path/to/folder/with/.dat files', required=True)
    parser.add_argument('--debug', action='store_true', help='Print layers', required=False)
    parser.add_argument('--strict', action='store_true', help='Cross-layer validation', required=False)
    args = parser.parse_args()

    _, retVal = validate_and_coverage(args.input, args.protocol, args.debug, args.strict)
    return retVal

if __name__ == "__main__":
    exit(main())
