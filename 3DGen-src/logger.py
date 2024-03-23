import json 

class MessageLogger:
    """
    Log agent message history
    """
    def __init__(self, filename):
        self.filename = filename

    def log_message(self, message):
        try:
            with open(self.filename, "a") as file:
                file.write(json.dumps(message) + "\n")
        except IOError as e:
            print(f"Error writing to log file: {e}")
            
            
    def log_rag_results(self, code, context):
        #build json object
        results = {
            "code": code,
            "context": context
        }
        try:
            with open(self.filename, "a") as file:
                file.write(json.dumps(results) + "\n")
        except IOError as e:
            print(f"Error writing to log file: {e}")