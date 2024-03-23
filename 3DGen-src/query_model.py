from tenacity import (
    retry,
    stop_after_attempt,
    wait_random_exponential,
)  
from langchain.prompts import load_prompt
from openai import AzureOpenAI
from dotenv import load_dotenv
import os

client = None

def API_setup():
    load_dotenv()
    global client
    client = AzureOpenAI(
        api_key=os.getenv("OPENAI_API_KEY"),
        azure_endpoint=os.getenv("OPENAI_API_BASE"),
        api_version="2023-08-01-preview",
    )
    
@retry(wait=wait_random_exponential(min=1, max=60), stop=stop_after_attempt(100))
def clean_RFC(data):
    API_setup()
    print("Cleaning RFC...")
    try:
        response = client.chat.completions.create(
            model="gpt-4-32k",
            messages=[{"role": "system", "content": "You are an expert at cleaning documents to remove unneeded information, while retaining the rest of the document."},
                     {"role": "user", "content" : f"Given the following RFC, retain all infromation about the header/message specification, all ascii diagrams, and important constraints about fields in message headers. Drop things like the introduction and references. Leave the rest untouched, do not summarize or comment. \n\n {data}"}],
            temperature=0.0,
            n = 1
        )
    except Exception as e:
        print(e)

    return response.choices[0].message.content