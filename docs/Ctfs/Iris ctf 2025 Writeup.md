Solves: Password manager(web)
## Password manager
#langs/go 
A go challenge. Reading the code, we see the routing function with an interesting comment
```go
func pages(w http.ResponseWriter, r *http.Request) {
	// You. Shall. Not. Path traverse!
	path := PathReplacer.Replace(r.URL.Path)

	if path == "/" {
		homepage(w, r)
		return
	}

	if path == "/login" {
		login(w, r)
		return
	}

	if path == "/getpasswords" {
		getpasswords(w, r)
		return
	}

	fullPath := "./pages" + path

	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		notfound(w, r)
		return
	}

	http.ServeFile(w, r, fullPath)
}
```
It seems any undefined routes fallback to a static file being served from `./pages`. There seems to be a function to prevent path traversal, yet checking the function we can see it is flawed.
```go
var PathReplacer = strings.NewReplacer(
	"../", "",
)
```
All this replacer does is remove occurances of `../` to prevent us moving up a directory. However, it will not remove nested a  `../`, allowing us to path traverse:
`..././` -> `../`
Checking out `..././users.json`, we are given the login details of a user:
```json
{
    "skat": "rf=easy-its+just&spicysines123!@"
}
```
From there, we can login as that user to obtain the flag. `irisctf{l00k5_l1k3_w3_h4v3_70_t34ch_sk47_h0w_70_r3m3mb3r_s7uff}`
> Notes: `....//` will get normalised into `..../` so that is invalid.
# Post ctf lessons
Official writeups at TODO
Author writeups: https://github.com/Seraphin-/ctf/tree/master/2025/irisctf
Full clear writeup at https://ireland.re/posts/irisctf_2025/
## Political
#misc/admin-bot
This is an admin bot challenge with the filter being chrome's [UrlBlockList](https://chromeenterprise.google/policies/#URLBlocklist) policy. Our goal is to first claim a token then make the bot visit the `/giveflag` endpoint with our token to make it valid. From there, we can visit `/redeem` with that token to get the flag.
```js
  async function load_url(socket, data) {
    let url = data.toString().trim();
    console.log(`checking url: ${url}`);
    // replace with your server as needed
    if (!url.startsWith('http://localhost:1337/') && !url.startsWith('https://localhost:1337/')) {
      socket.state = 'ERROR';
      socket.write('Invalid URL (must start with http:// or https://).\n');
      socket.destroy();
      return;
    }
    socket.state = 'LOADED';
    let cookie = JSON.parse(fs.readFileSync('/home/user/cookie'));

    const context = await browser.createBrowserContext();
    const page = await context.newPage();
    await page.setJavaScriptEnabled(false);
    await page.setCookie(cookie);
    socket.write(`Loading page ${url}.\n`);
    setTimeout(()=>{
      try {
        context.close();
        socket.write('timeout\n');
        socket.destroy();
      } catch (err) {
        console.log(`err: ${err}`);
      }
    }, BOT_TIMEOUT);
    await page.goto(url);
  }
```
As seen from the dockerfile
```Dockerfile
...
RUN mkdir -p /etc/opt/chrome_for_testing/policies/managed/
RUN chmod -R -w /etc/opt/chrome_for_testing/
COPY policy.json /etc/opt/chrome_for_testing/policies/managed/
...
```
, the `policy.json` file is created with these blocklists:
```json
{
	"URLBlocklist": ["*/giveflag", "*?token=*"]
}
```
The second blocklist seems easy to bypass with a query like `?a=lol&token=...`, however one should first [**consult the documentation**](https://support.google.com/chrome/a/answer/9942583#zippy=%2Curl-blocklist-examples) to understand how the blocklist functions(which I didn't do and wasted a lot of time on). As from the docs, it is stated that "Token order is ignored during matching.", hence the query would still be blocked.
### The solution
Turns out, url encoding the url will bypass both filters. 
### Lessons learnt
* Url encoding should be tried a bit more in admin bot challenges, given that chrome doesn't bother decoding the url 
* Always try to replicate the important parts of the challenge environment to be as easy to debug as possible. In this case, I should've also replicated the chromium browser and inputted urls directly into it to see if they were getting blocked. 
## Bad todo
Skipped this challenge but authors' writeup at https://rph.space/blog/irisctf-2025-bad-todo/ 
# Webwebhookhook
#langs/java
#misc/language-quirks
A challenge where we can create and ping webhooks to get them to send data to their configured urls. 
```kotlin
class StateType(
        hook: String,
        var template: String,
        var response: String
        ) {
    var hook: URL = URI.create(hook).toURL()
}
object State {
    var arr = ArrayList<StateType>()
}
/* ... (main file) */
const val FLAG = "irisctf{test_flag}";

fun main(args: Array<String>) {
    // TODO We need a way to get this webhook to send to a domain we control.
    State.arr.add(StateType(
            "http://example.com/admin",
            "{\"data\": _DATA_, \"flag\": \"" + FLAG + "\"}", // TODO not actually json object, we could mess with this
            "{\"response\": \"ok\"}"))
    runApplication<WebwebhookhookApplication>(*args)
}

```
Checking the endpoint for pinging webhooks, we see something interesting:
```kotlin
    @PostMapping("/webhook")
    @ResponseBody
    fun webhook(@RequestParam("hook") hook_str: String, @RequestBody body: String, @RequestHeader("Content-Type") contentType: String, model: Model): String {
        var hook = URI.create(hook_str).toURL();
        for (h in State.arr) {
            if(h.hook == hook) {
                var newBody = h.template.replace("_DATA_", body);
                var conn = hook.openConnection() as? HttpURLConnection; // TODO Interestingly, the url we supply is used
                if(conn === null) break;
                conn.requestMethod = "POST";
                conn.doOutput = true;
                conn.setFixedLengthStreamingMode(newBody.length);
                conn.setRequestProperty("Content-Type", contentType);
                conn.connect()
                conn.outputStream.use { outputStream ->
                    outputStream.write(newBody.toByteArray())
                }

                return h.response
            }
        }
        return "{\"result\": \"fail\"}"
    }
```
The function checks through each webhook and compares its url against a `URL` we provide. Once it finds a webhook with matching urls, it will send a post request to its configured url. However, it should be noted that the url it uses is the one we send, not the configured url(even though they should be *equal*). This means if we could have 2 urls that are said to be equal yet point to different addresses, we could get the flag sent to us instead. In this case, our url should equal `http://example.com/admin`. 
### Java's URL equality
Turns out, java checks urls for equality by resolving them (https://news.ycombinator.com/item?id=21765788). By performing a DNS rebinding attack, we can get the url to first resolve to `example.com`  and quickly swap records to point to our own address. 
While I am too lazy to actually figure out how the attack is carried out, I have some resources:
* https://ireland.re/posts/irisctf_2025/#webwebwebhookhook-16-solves
	* Used https://requestrepo.com/
* https://github.com/nccgroup/singularity
	* Seems to have a public instance(?) at http://rebind.it:8080/manager.html