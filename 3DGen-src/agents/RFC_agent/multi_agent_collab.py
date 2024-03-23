from dotenv import load_dotenv
import os
import argparse
import json
import autogen
from test_utils import evaluate_code
import agents.RFC_agent.multi_agent_prompts as prompts
import time
from agents.RFC_agent.query_RFC import get_context
from logger import MessageLogger
from query_model import clean_RFC

def generate_config(args):
    with open("config.json", "r") as f:
        config = json.load(f)
        config["rfc_path"] = args.rfc
        config["tests"] = args.tests

    with open("config.json", "w") as f:
        json.dump(config, f)
        
    return config

def print_messages(recipient, messages, sender, config): 
    if "callback" in config and  config["callback"] is not None:
        callback = config["callback"]
        callback(sender, recipient, messages[-1])
    #build json object with message content
    message = {"n":f"{len(messages)}", "sender": f"{sender.name}", "recipient": f"{recipient.name}", "content": messages[-1]}
    logger.log_message(message)
    return False, None  # required to ensure the agent communication flow continues

def setup():
    load_dotenv()
    azure_api_key = str(os.getenv("OPENAI_API_KEY"))
    base_url = str(os.getenv("OPENAI_API_BASE"))

    return [
        {
            "model": model_version,
            "api_key": azure_api_key,
            "base_url": base_url,
            "api_type": "azure",
            "api_version": "2023-08-01-preview",
        }
        for model_version in ["gpt-4-32k"]
    ]

def parse_command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rfc", type=str, required=True, help="rfc link")
    parser.add_argument("--proto", type=str, required=True, help="Protocol")
    parser.add_argument("--manual", type=str, required=False, help="Path to a 3D manual")
    parser.add_argument("--tests", type=str, required=False, help="path to tests", default="none")  
    parser.add_argument("--n", type=int, required=False, help="Number of refinements loops allowed", default=15) 
    parser.add_argument("--temp", type=float, required=False, help="Main agent loop temperature", default=1.0)   
    parser.add_argument("--attempt", type=int, required=False, help="Number of attempts", default=5)  
    return parser.parse_args()

def agent_config(llm_config, manual, example, n):
    developer = autogen.AssistantAgent(
        name="Developer",
        llm_config=llm_config,
        is_termination_msg=lambda x: x.get("content", "") and "All packets accepted" in x.get("content", "").rstrip(),
        max_consecutive_auto_reply = n,
        system_message=prompts.get_developer_prompt(manual, example),
    )

    executor = autogen.UserProxyAgent(
        name="Executor",
        system_message="Executor. Your job is to execute all code given to you. Execute the 3d code written by the Developer and report the result. You pass as input to the executor the code and the module name of the entrypoint function. You can only execute code using the provided function.",
        human_input_mode="NEVER",
        code_execution_config={"last_n_messages": 1, "work_dir": "coding"},
    )
    
    executor.register_function(function_map={"evaluate_code": evaluate_code})
    developer.register_reply([autogen.Agent, None], reply_func=print_messages, config={"callback": None},)

    return [developer, executor]

def get_agent_skills(config_list, args):
    llm_config = {
        "functions": [
            {
                "name": "evaluate_code",
                "description": "Call this function to run 3d code - checks syntax, runs tests, and returns execution results and errors.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "code": {
                            "type": "string",
                            "description": "The generated code.",
                        },
                        "module_name": {
                            "type": "string",
                            "description": "The name of the entrypoint function.",
                        },
                        "protocol": {
                            "type": "string",
                            "description": "The name of the protocol.",
                        }
                    },
                    "required": ["code", "module_name", "protocol"],
                },
            }
        ],
        "config_list": config_list,
        "timeout": 120,
        "cache_seed": None,
        "temperature": args.temp
    }
    
    return llm_config

def agent_loop(config_list, args):
    rfc_path = args.rfc
    manual_path= args.manual
    proto = args.proto
    n = args.n 
    
    llm_config = get_agent_skills(config_list, args)

    if ".json" in rfc_path:
        with open(rfc_path, "r") as f:
            rfc = json.load(f)
    else:
        rfc = get_context(rfc_path)
        rfc = clean_RFC(rfc)

    if manual_path is not None:
        with open(manual_path, "r") as f:
            manual = f.read()
    else:
        with open("3d_manuals/3d_syntax_check.txt", "r") as f:
            manual = f.read()

    with open("examples/multi_agent_example.txt", "r") as f:
        example = f.read()

    agent_list = agent_config(llm_config, manual, example, n)
    agent_list[1].initiate_chat(
    agent_list[0],
    message=prompts.get_task_prompt(rfc, proto)
    )

    

if __name__ == "__main__":
    args = parse_command_line_args()
    generate_config(args)
    config_list = setup()
    
    log_dir = "agents/RFC_agent/agent_log"
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    filename = os.path.join(log_dir, f"{args.proto}_{int(time.time())}.jsonl")

    logger = MessageLogger(filename)
    print("*"*50)
    print(f"Running with the following configuration: \n{args}")
    print(f"Logging internal agent messages to {filename}")
    
    for i in range(args.attempt):
        print("*"*50)
        print(f"Attempt {i+1}")
        print("*"*50)

        request_success = False
        while not request_success:
            try:
                agent_loop(config_list, args)
                request_success = True
            except Exception as e:
                print(f"Error: {e}")
                print("Retrying......")
                time.sleep(60)
                continue
        
        success = False
        syntax_refinements = 0
        packet_refinements = 0
        spec_file =""
        with open(filename, "r") as f:
            for line in f:
                if "All packets accepted" in line:
                    success = True
                    spec_file = line.split("everparse_files/")[-1].split(".3d")[0]
                    spec_file = "everparse_files/" + spec_file + ".3d"
                    spec_file = os.path.abspath(spec_file)
                else:
                    success = False
                if "Processing files: everparse_files/" in line or "syntax error" in line:
                    syntax_refinements += 1
                if "Packet failed" in line:
                    packet_refinements += 1  
        
        results = {"protocol": args.proto, "params" : f"{str(args)}", "success": success, "filename": filename, "syntax_refinements": syntax_refinements, "packet_refinements": packet_refinements}
        print(results)
        with open(filename, "a") as f:
            json.dump(results, f)
            
        experiment_dir = os.path.abspath("experiments/RFCs/")
        problem_dir = os.path.join(experiment_dir, args.proto)
        
        if not os.path.exists(problem_dir):
            os.mkdir(problem_dir)
        if not os.path.exists(experiment_dir):
            os.mkdir(experiment_dir)
        print(f"Copying {filename} to {problem_dir}")
        call = f"cp {filename} {problem_dir}"
        os.system(call)
        print(f"Copying {spec_file} to {problem_dir}")
        call = f"cp {spec_file} {problem_dir}"
        os.system(call)
   
        
       
    
    
