import os
import subprocess
from clean_response import   process_packet_results
import json 
import datetime


config = {}
everparse_path = ""
test_path = ""

def setup():
    with open("config.json", "r") as f:
        global config 
        global everparse_path
        global test_path
        
        config = json.load(f)
        everparse_path = config["everparse_path"]
        try:
            test_path = config["tests"]
        except:
            test_path = None

def response_to_tmp(response, protocol, message_name):
    timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    dir = f"everparse_files/{protocol}/{message_name}"
    filename = f"{dir}/{message_name}_{timestamp}.3d"

    if not os.path.exists(dir):
        os.makedirs(dir)
    try:
        with open(filename, "w") as f:
            f.write(response)
    except Exception as e:
        print(e)
        print(f"Error writing to {filename}")
  
    return dir, filename



def check_packets(folder, exe_dir):
    packet_dir = folder
    z3_dir = os.path.join(packet_dir, "z3")
    z3_dir = os.path.abspath(z3_dir)
    dirs = [z3_dir]

    packet_label_path = os.path.join(packet_dir, z3_dir, "z3_packet_labels.json")
    packet_label_path = os.path.abspath(packet_label_path)
    with open(packet_label_path, "r") as f:
        packet_labels = json.load(f)
    for dir in dirs:
        print('*'*50)
        print("Checking packets in: ", dir)
        for packet in os.listdir(dir):
            if packet.endswith(".dat"):
                call = f"{exe_dir}/test.exe {dir}/{packet}"
                print(call)
                output = subprocess.Popen(call, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                output_dump = output.stdout.read().decode("utf-8")
                output_err = output.stderr.read().decode("utf-8")
                feedback, result =  process_packet_results(output_err, output_dump)
    

                if packet in packet_labels:
                    print("Ground truth labels found for packet: ", packet)
                    print("Ground truth label: ", packet_labels[packet])
                    packet_label = str(packet_labels[packet][0]).lower()
                    result_label = str(result['accepted']).lower()
                    print("Packet label: ", packet_label)
                    print("Result: ", result_label)
                    
                    if packet_label == result_label:
                        print(f"Packet {packet} passes")

                    else:
                        packet_status = "passes" if packet_label == 'true' else "fails"
                        with open(f"{dir}/{packet}", "rb") as f:
                            packet_contents = f.read()
                        if "packet malformed" in feedback:
                            feedback = "the packet is not a valid packet for this protocol"
                        
                        return f"The generated spec is incorrect. Please refer back to the RFC and modify the spec so that the packet {packet_status}. Error message: {feedback} for the following packet: \n  {packet_contents}. \n A hint about why this packet should {packet_status} :  {packet_labels[packet]}"
                    
                else:
                    print("No ground truth labels found for packet: ", packet)
                    return f"No ground truth labels found for packet: {packet}. Please add ground truth labels for all packets in the test set"
            
        print(f"All packets in {dir} validated as expected")
        return "All packets accepted"


def evaluate_code(code, module_name, protocol):
    setup()
    timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    if not os.path.exists(f"everparse_files/{module_name}"):
        os.makedirs(f"everparse_files/{module_name}")
        
    filename = f"everparse_files/{module_name}/Tmp_{timestamp}.3d"
    with open(filename, "w") as f:
        f.write(code)
    
    module = f"Tmp_{timestamp}.{module_name}"
    call = f"bash {everparse_path} {filename} --test_checker {module} --odir ./everparse_files/{module_name}/"
    output = subprocess.Popen(
        call, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    output_dump = output.stdout.read().decode("utf-8")
    output_err = output.stderr.read().decode("utf-8")

    if "EverParse succeeded" in output_dump:
        print("Specification is syntactically valid... checking tests")
        output_err = ""
   
        if "none" not in test_path:
            packet_result = check_packets(test_path, f"everparse_files/{module_name}/")      
            output_dump = f"{packet_result} for file {filename}"
  
        
    elif "Error 168" in output_dump:
        output_dump = "Syntax error, type is a reserved keyword"
    else:
        return output_err, output_dump

    return output_err, output_dump


