TODO better name for document
## No FA
#libs/flask 
The challenge gives us a:
* app.py
* users.db (some leaked data apparently)

Viewing the database, it seems to contain a bunch of usernames with usernames and hashed passwords. Notably, there is the `admin` user, which is required for us to get the flag:
```python
    flag = "No flag for you!!"
    if session.get('username') == 'admin':
        flag = os.getenv('FLAG')
```
Our first step is to crack the admin password(hopefully). We try this with hashcat: `hashcat -m 1400 -a 0 hashes.txt ./rockyou.txt `
Thankfully it managed to crack the password, giving us the password `apple@123`.
The admin account does have 2fa enabled, so let's review how to bypass that. In the login code, we see this:
```python
                session['otp_secret'] = otp
                session['otp_timestamp'] = time.time()
                session['username'] = username
                session['logged'] = 'false'
```
The otp secret is actually stored in the flask session, which is signed(it prevents tampering) but not encrypted and hence can be [decoded](https://www.kirsle.net/wizards/flask-session.cgi) . All we need to do is open inspect element and steal the session cookie. With that, we are able to login and get the flag: `picoCTF{n0_r4t3_n0_4uth_6db141c5}`