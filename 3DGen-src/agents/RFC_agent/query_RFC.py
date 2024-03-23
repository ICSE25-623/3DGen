import os
from langchain_community.document_loaders import UnstructuredURLLoader



def pretty_print_docs(docs):
    print(
        f"\n{'-' * 100}\n".join(
            [f"Document {i+1}:\n\n" + d.page_content for i, d in enumerate(docs)]
        )
    )
    
def get_context(rfc): 
    print("Extracting RFC from link....")  
    urls = [rfc]
    loader = UnstructuredURLLoader(urls=urls)
    data = loader.load()
    
    return data

