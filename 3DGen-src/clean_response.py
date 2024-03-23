

def process_packet_results(output_err, output_dump):
    feedback = ""
    result = {"accepted": 0}
    if "ACCEPTED" in output_dump:
            result["accepted"] = "true"
            feedback = f"Success! Packet accepted" + "\n\n" + output_dump
    else:
        feedback = "Packet failed" + "\n\n" + output_dump
        result["accepted"] = "false"
    return feedback, result


