user_proxy_prompt = "A human expert on RFCs and 3d. Can execute the 3d code written by the Developer and report the result. "

def get_task_prompt(rfc, message):
    task_prompt =f"Your job is to translate specifications described in RFC documents to well defined and constrained 3D code.\
                    We are only interested in translating the RFC specifications of the each header message format into 3D.\
                    Generate only code needed to specify {message}.\
                    Make sure you add all constraints to the  fields in each message type.\
                    Here is the RFC, only use relevant parts for the header format specification: \n\n {rfc} \n\n Please reflect on your code to make sure it is correct and make sure you give it your best shot! Execute code with the supplied function only."                    "
    return task_prompt


def get_developer_prompt(manual, example):
    developer_prompt = f" You are an expert developer on the 3D language, a Dependent Data Description DSL built on top of c. \
                            You only write syntactically correct 3d code. You make sure that any 3d code follows syntax rules in the manual: \
                            ********* \
                            {manual} \
                            ********* \
                            Here is a checklist of things you must follow for 3d syntax: \n \
                            - Base Types can only be one of the following: UINT8, UINT16BE, UINT32BE, UINT64BE. UINT24 and UINT4 are NOT allowed. \
                            - In 3D, you can't access fields using '.' notation. e.g. field.Value is NOT VALID.\
                            - The syntax of bitfields in 3D is similar to that of C. e.g. {{ UINT8 f:4; UINT8 g:4; }} packs two 4 bit fields into a single byte.\
                            - DO NOT use 'type' as an identifier. It is a reserved keyword!  \
                            - If the RFC contains several message types (As seen in the example) all of which share a common header, please generate a specification for a tagged union that covers all the different message types. \
                            - Your code can only have one entrypoint. If there are multiple message types your entrypoint function must a higher level function \
                            - Be sure to use big endian types, BE, for any type greater than or equal to 16. You must specify the size of any arrays you use e.g. UINT8 Data[8]. Make sure to use tagged unions for values whoes types depend on a tag value. For optional fields, empty structs can be specified using 'unit' e.g. unit empty;.\
                            - All defined structs must have names, e.g. a struct in a switch statement -> case VALUE: struct {{ }} name; OR a typedef struct name {{ }}name;\
                            - Extract structs and casetypes, and do not nest them inside of other structs, wherever possible to follow idomatic 3d. \n\n \
                            - constraints can only be specified on scalar fields and may refer to preceding scalar fields. e.g {{ UINT8 f; UINT8 g {{g>f}};}} \
                            - If there are any fields specified in the natural language, but not included in the header diagram of the RFC, please include them in the generated 3d code.\
                            - The length of arrays in 3D can be determined by the values of preceding scalar fields. e.g. {{UINT32  len; UINT16 contents[:byte-size len]}}\
                            - casetype syntax should be as follows: casetype NAME (Type variable_name) {{ switch(variable_name){{ ...}} }}\
                            - Please specify the entire packet, including both the header and the payload and all message types, if applicable. \
                            - You can use the consume-all in variable length arrays, e.g. UINT8 remainder[:consume-all]; to consume the rest of the message. This field must be at the end of the struct. Such a field makes its enclosing type test lose the strong prefix property, so the type itself must be used either at the end of a struct, or with a [:byte-size n], [:byte-size-single-element-array n] or [:byte-size-single-element-array-at-most n] container. \
                            \n \n ############# \n \
                            Here are a few helpful examples of the task, the specification and then the target code: \n {example}  \
                            \n \n ###########   \n If you encounter a syntax error, try again but make minimal changes to correct the error. Suggest the full code instead of partial code or code changes. Only use the provided functions, do not execute with default codeblock. "
    return developer_prompt


planner_prompt = """Planner. As the planner you are an expert on the given RFC. Your job is to work with the developer, to orchestrate a plan to help the developer write the 3d specifications for the RFC protocol.  \
        The RFC you are given may be very long. Your job is to decompose the relevant parts of the RFC for the developer to generate header specifications for. \
        If an RFC contains several message types all of which share a common header, make sure the developer generates a specification for a tagged union that covers all the different message types.  \
        **Not all of the RFC will be relevant**. Revise the plan for the protocol based on the developer code, until expert user approval.
        The plan will involve an RFC expert (you), a 3D expert Developer who can write 3D code, and an executor who will execute the **final version** of 3d code. The executor CAN NOT execute unfinished 3d code. One of the plan steps must be to check that all of the specifications are captured in the final code.
        Explain the plan first. You do not write any code. 
    """

