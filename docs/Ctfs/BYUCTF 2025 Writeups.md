Solves: Red This(web), Willy Wonka Web(web), Cooking Flask(web), JWTF(web)
## Red This
#langs/python 
We have some weird quote fetching website which uses redis as its database. In order to get the flag quote, we need to be admin
```python
@app.route('/get_quote', methods=['POST'])
def getQuote():
    username = flask.session.get('username')
    person = flask.request.form.get('famous_person')
    quote = [person, '']
    if "flag" in person and username != "admin": # TODO we can only retrieve the flag if we have the admin username
        quote[1] = "Nope"
    else: 
        quote[1] = getData(person)
    adminOptions = getAdminOptions(username)
    return flask.render_template('index.html', adminOptions=adminOptions, quote=quote)
```
When reviewing the login endpoint, we can see that it also uses `getData()`
```python
@app.route('/login', methods=['POST', 'GET'])
def login():
     # return register page 
    if flask.request.method == 'GET':
        error = flask.request.args.get('error')
        return flask.render_template('login.html', error=error)
    
    username = flask.request.form.get("username").lower()
    password = flask.request.form.get("password")

    ## error check
    if not username or not password:
        return flask.redirect('/login?error=Missing+fields')
    
    # check username and password
    dbUser = getData(username)
    dbPassword = getData(username + "_password")
    
    if dbUser == "User" and dbPassword == password:
        flask.session['username'] = username
        return flask.redirect('/')
    return flask.redirect('/login?error=Bad+login')
```
It seems `getData()` only accepts a single key to search for, which means somehow all the data is retrieved from the same database perhaps?
```python
def getData(key):
    db = redis.Redis(host=HOST, port=6379, decode_responses=True)
    value = db.get(key)
    return value
```
Indeed, checking `insert.redis` we see user data and quotes are all stored in the same database
```redis
set key value
set "FDR" "The only thing we have to fear is fear itself."
set "Shakespeare" "To be, or not to be, that is the question."
set "Mandela" "The greatest glory in living lies not in never falling, but in rising every time we fall."
set "Theodore Roosevelt" "Believe you can and you're halfway there."
set "Disney" "All our dreams can come true, if we have the courage to pursue them."

set "admin" "User"
set "admin_password" "prod_has_a_different_password"
set "fake_flag" "I told you"
set "flag_" "byuctf{test_flag}"
JSON.SET admin_options $ '["hints", "fake_flag", "flag_"]'

```
> Actually, I'm not sure if redis has a concept of databases

This means we could fetch `admin_password` as a quote to steal the admin password and login as admin. 
![[Pasted image 20250518113551.png]]
With that, we can get the flag
![[Pasted image 20250518113745.png]]
`byuctf{al1w4ys_s2n1tize_1nput-5ed1s_eik4oc85nxz}`
# Willy Wonka Web
#langs/javascript 
#libs/apache
We are given a simple flag server proxied behind apache. It seems all we need to do is set the `a: admin` header
```js
const express = require('express');
const fs = require('fs');

const app = express()
const FLAG = fs.readFileSync('flag.txt', { encoding: 'utf8', flag: 'r' }).trim()
const PORT = 3000

app.get('/', async (req, res) => {
    if (req.header('a') && req.header('a') === 'admin') {
        return res.send(FLAG);
    }
    return res.send('Hello '+req.query.name.replace("<","").replace(">","")+'!');
});

app.listen(PORT, async () => {
    console.log(`Listening on ${PORT}`)
});
```
Unfortunately, the `httpd.conf` file is very simple and seems to strip off any `a` headers.
```apacheconf
LoadModule rewrite_module modules/mod_rewrite.so
LoadModule proxy_module modules/mod_proxy.so
LoadModule proxy_http_module modules/mod_proxy_http.so

<VirtualHost *:80>

    ServerName localhost
    DocumentRoot /usr/local/apache2/htdocs

    RewriteEngine on
    RewriteRule "^/name/(.*)" "http://backend:3000/?name=$1" [P]
    ProxyPassReverse "/name/" "http://backend:3000/"

    RequestHeader unset A
    RequestHeader unset a

</VirtualHost>
```
There still seems to be nothing interesting, so let's dig further. Perhaps we should check for any vulnerabilities in apache.
```dockerfile
FROM httpd:2.4.55

COPY httpd.conf /tmp/httpd.conf
RUN cat /tmp/httpd.conf >> /usr/local/apache2/conf/httpd.conf
```
Aha!
![[Pasted image 20250518120702.png]]
Checking through the [apache docs](https://httpd.apache.org/security/vulnerabilities_24.html), we see this specific vulnerability listed.
![[Pasted image 20250518120816.png]]
It seems oddly similar to the configuration we are given. Perhaps using that, we could smuggle the header in? Passing the vulnerability description and config files to deepseek, I got it to generate a payload for me(Yes I was too lazy to actually understand the exploit)
![[Pasted image 20250518121102.png]]
With a little modification of adding an extra `\r\n` at the end of our request, we can get the flag.
> Not sure why the original payload of only one `\r\n` at the end didn't work. Perhaps we are actually signifying the start of a new request with `\r\n\r\n`?
> ![[Pasted image 20250518121910.png]]

![[Pasted image 20250518121937.png]]
`byuctf{i_never_liked_w1lly_wonka}`
# Cooking flask
#langs/python, #langs/sql/sqlite
We are given a recipe querying website where we can search for recipes by name or by tags.
![[Pasted image 20250518124505.png]]
When we perform a search, a get request with all our search parameters are sent. Changing the tags to a quote, we are greeted by a sql error and the werkzueg debugger.
![[Pasted image 20250518125700.png]]
> At this point, I was confused by the double quote in the error and hadn't thought of trying to close the dangling `')` as hinted by the syntax error. 

Unable to guess how the query was like, I decided to try more inputs and add another `tags` query parameter. This time, I got a slightly more helpful error message
![[Pasted image 20250518130136.png]]
From that, I could infer the tags were probably placed inside the `'%""%'` and could then make a payload to escape the query.
![[Pasted image 20250518130358.png]]
The next step was to try to use `union` to exfiltrate information about the database. First, we should find out how many columns we are expected to return.
![[Pasted image 20250518130554.png]]
When performing the union query, the server then threw an error stating it was expecting a string, not an integer. 
![[Pasted image 20250518130900.png]]Since we don't know which column exactly needs to be a string, we just select everything as a string instead. This time, we get a different error. Wohoo!
![[Pasted image 20250518131505.png]]
For the 3rd field, it seems  pydantic [expects a date](https://docs.pydantic.dev/2.11/errors/validation_errors/#date_from_datetime_inexact), so we'll just copy the valid example given. For the 7th field, it seems to expect a list.
![[Pasted image 20250518131819.png]]
Now that we finally have a valid response, we can start exfiltrating data out of the database.
![[Pasted image 20250518131916.png]]
Since we have a `user` table, we should probably see what passwords there are. A query like `') union select '1',(SELECT group_concat(password) FROM user),'2023-01-01','4','5','6','[]','8';--` helps leak that.
![[Pasted image 20250518132046.png]]
`byuctf{pl34s3_p4r4m3t3r1z3_y0ur_1nputs_4nd_h4sh_p4ssw0rds}`
> Fun fact, you can actually click on lines in the debugger and it'll reveal even more code. If I had done that, I would've seen how the query was constructed
> ![[Pasted image 20250518125950.png]]
## JWTF
#langs/python 
> Challenge source code has been modified by me for debugging

We are given a challenge where we need to be admin in order to get the flag.
```python
@app.route('/flag', methods=['GET'])
def flag():
    session = request.cookies.get('session', None).strip().replace('=','') # TODO Actually base64 also allow =/ chars? Turns out it also allows whitespace
    print("Stripped session is ", session)
    if session is None:
        print("Lacking session")
        return redirect('/?e=nosession')
    
    # check if the session is in the JRL
    if session in jrl: # TODO Doesn't jwt allow changing metadata without changing signature(Nope nvm)
        print("In jrl")
        return redirect('/?e=inlist')

    try:
        payload = jwt.decode(session, APP_SECRET, algorithms=["HS256"])
        if payload['admin'] == True:
            return FLAG # TODO FLAG HERE
        else:
            print("Not admin")
            return redirect('/?e=notadmin')
    except Exception as e:
        print("Exception: ", e)
        return redirect('/?e=decodefail')
```
While we are provided with a valid jwt token,
```python
jrl = [
    jwt.encode({"admin": True, "uid": '1337'}, APP_SECRET, algorithm="HS256")
]
...
@app.route('/jrl', methods=['GET'])
def jrl_endpoint():
    return jsonify(jrl)
```
it is blacklisted. However, the blacklist uses an exact match of the jwt token and perhaps we can modify parts of it without voiding its validity. Initially, I had incorrectly thought we could modify the headers without changing the signature. While not true, it gave the idea of modifying the encoded token while keeping the decoded data the same. Unfortunately, it seems the signature is generated from the raw token and not the decoded data, meaning even adding a space will modify the token's signature
```python
import jwt
from jwt import utils
import os

APP_SECRET = os.urandom(32).hex()

jrl = jwt.encode({"admin": True, "uid": '1337'}, APP_SECRET, algorithm="HS256")
chunks = jrl.split(".")
modified = '.'.join([chunks[0]+" ", *chunks[1:]])

print(jrl)
print(modified)

jwt.decode(jrl, APP_SECRET, algorithms=["HS256"])
jwt.decode(modified, APP_SECRET, algorithms=["HS256"])
```
![[Pasted image 20250518171051.png]]
If neither the headers nor the data can be changed, what about the signature portion of the token?
```python
import jwt
from jwt import utils
import os

APP_SECRET = os.urandom(32).hex()

jrl = jwt.encode({"admin": True, "uid": '1337'}, APP_SECRET, algorithm="HS256")
chunks = jrl.split(".")
modified = ".".join(chunks[:2] + [" " +chunks[2]])

print(jrl)
print(modified)

jwt.decode(jrl, APP_SECRET, algorithms=["HS256"])
jwt.decode(modified, APP_SECRET, algorithms=["HS256"])
```
This time, we are given a different error telling us our padding is wrong
![[Pasted image 20250518171619.png]]
Diving deeper into `base64url_decode()`, we see it incorrectly tries to pad our extra space into a multiple of 4
```python
def base64url_decode(input: Union[bytes, str]) -> bytes:
    input_bytes = force_bytes(input)

    rem = len(input_bytes) % 4

    if rem > 0:
        input_bytes += b"=" * (4 - rem)

    return base64.urlsafe_b64decode(input_bytes)
```
> At this point, I could've just padded it with 4 spaces instead but I kinda missed this

Let's go even deeper, into `base64.urlsafe_b64decode()`
```python
def urlsafe_b64decode(s):
    """Decode bytes using the URL- and filesystem-safe Base64 alphabet.

    Argument s is a bytes-like object or ASCII string to decode.  The result
    is returned as a bytes object.  A binascii.Error is raised if the input
    is incorrectly padded.  Characters that are not in the URL-safe base-64
    alphabet, and are not a plus '+' or slash '/', are discarded prior to the
    padding check.

    The alphabet uses '-' instead of '+' and '_' instead of '/'.
    """
    s = _bytes_from_decode_data(s)
    s = s.translate(_urlsafe_decode_translation)
    return b64decode(s)
```
In its docs, it mentions discarding discarding non url-safe base-64 alphabets. That means we could supply it a unicode character like `😊` and have it discarded, hence keeping the signature valid.  Testing this, we see the jwt tokens are both valid
```python
import jwt
from jwt import utils
import os

APP_SECRET = os.urandom(32).hex()

jrl = jwt.encode({"admin": True, "uid": '1337'}, APP_SECRET, algorithm="HS256")
chunks = jrl.split(".")
modified = ".".join(chunks[:2] + ["😊" +chunks[2]])

print(jrl)
print(modified)

jwt.decode(jrl, APP_SECRET, algorithms=["HS256"])
jwt.decode(modified, APP_SECRET, algorithms=["HS256"])
```
Hence, all we need to do is add a smiley emoji before the start of our signature, giving us the flag.
![[Pasted image 20250518172305.png]]
`byuctf{idk_if_this_means_anything_but_maybe_its_useful_somewhere_97ba5a70d94d}`
# Post ctf lessons
Source code and author writeups at https://github.com/BYU-CSA/BYUCTF-2025
* Has some useful notes on running infra too

