**At the point of writing, I do not have access to the challenges so everything is based off memory and what I have. For future reference in case I forget my solutions when the challenges are re-opened**

---
Web1
## A purrfect chat
We are given a website where we can input text to check if it matches the flag. Sending the input does not make any http requests, so we know the flag is checked locally.  Taking the bundled js file, we can see the last line seems to contain the compiled code. That line can be thrown into a js decompiler and beautifier, from which we have to manually reverse engineer the code.
Also, renaming variables is really helpful for your sanity. 
```js
Q.jsxs("div", {  
    className: "",  
    children: [  
        Q.jsx(MaybeJsxCompontent, { result: var2, value: var1 }),  
        Q.jsxs("div", {  
            className: "",  
            children: [  
                Q.jsx("input", { type: "text", className: "", placeholder: "flag", value: var1, onChange: (o) => setVar1(o.target.value) }),  
                Q.jsx("button", { className: "w-6", onClick: checkAns, children: Q.jsx("img", { src: Np, alt: "send", className: "" }) }),  
            ],  
        }),  
    ],  
})
```
```js
const [var1, setVar1] = He.useState(""),  
    [var2, setVar2] = He.useState(""),  
    checkAns = () => {  
    //  
        var1.length === 18 &&  
        var1[8] === "F"/*.charCodeAt() === parseInt("70")*/ &&  
        var1[1] === "e" /*.charCodeAt() === 101*/ &&  
        var1[13] === "3" &&  
        var1.slice(4, 7/*-11*/) === "ome"/*"You are awesome!".substr(-4, 3)*/ &&  
        var1[0].charCodeAt() === "W"/*parseInt(var1[8].charCodeAt()) + 17*/  
            ? setVar2("o") // <-- YOU WANT THIS  
            : setVar2("x");  
    };
```
```js
const Zi = (e) => {  
    // Prob some function to make a variable reactive?  
        (yc ? "production" : void 0) !== "production" && typeof e != "function" && console.warn("[DEPRECATED] Passing a vanilla store will be unsupported in a future version. Instead use `import { useStore } from 'zustand'`.");  
        const t = typeof e == "function" ? bd(e) : e,  
            n = (r, l) => xp(t, r, l);  
        return Object.assign(n, t), n;  
    },  
    _p = (e) => (e ? Zi(e) : Zi),  
    Cp = _p(() => ({ items: ["10", "11", 0, 1, 2, 3, 18, 176] }));
function MaybeJsxCompontent({ result: isaOorX, value: test }) {  
    const [text, setText] = He.useState("Please input the answer"),  
        l = ["10", "11", 0, 1, 2, 3, 18, 176]/*Cp((maybeArray) => maybeArray.items)*/,  
        o = () => /\)$/.test(test) && test[7] === "2"/*l[4].toString()*/ && test[9] === "r"/*.charCodeAt() === parseInt(100 + (l[7] % l[6]))*/ && test.slice(11, 13) === "nt" && test[2] === "1"/*l[3] + ""*/,  
        u = () => test[15] === "d" && test[3] === 'c'/*.charCodeAt() === 99*/ && test[14] === "n" /*.charCodeAt() === parseFloat(l[1] + l[2])*/ && test[10] === "0";  
    return (  
        He.useEffect(() => {  
            isaOorX === "o" && test[16] === ":"/*.charCodeAt() === 58*/ && o() && u() ? setText("Correct!") : isaOorX === "x" && setText("Try again :(");  
        }, [isaOorX]),  
            Q.jsx("span", { className: "", children: text })  
    );  
}
```
Putting everything together, we get `"We1come2Fr0nt3nd:)"`
## Traefik
This challenge has a simple basic auth protected web server.
This challenge got a suspiciously high number of solves within the first day. I thought it had something to do with the docker/nginx configuration but eventually decided to use hydra to try cracking the password since we knew the username(The password is hashed though). 
# Crypto 3?
We have a go file that seems to help us decrypt the aes encrypted text.
Upon running, we see that the file has 64 bytes, 2 bytes away from being a multiple of the cipher blocksize
The solution? Just bruteforce the 2 missing bytes. (Code was translated into kotlin by chatgpt)
```kotlin
fun main() {  
	// Ugly, but does the job
    val encryptedData = "6f7e9007dd0882f3f320a08690a230b84fcfa66b483dc4f4352123276622af4cc5c656bf0171c36271700f8f4f0f41d14d7c20baec601c70f670acc8b6037"  
    val ciphertext = hexStringToByteArray(encryptedData)  
    repeat(256) {  
        val byte1 = it.floorDiv(16).toByte()  
        val byte2 = it.mod(16).toByte()  
        val d = decrypt(ciphertext + byte1 + byte2)  
        if (d != "") println(d)  
    }  
  
}  
fun hexStringToByteArray(s: String): ByteArray {  
    val len = s.length  
    return ByteArray(len / 2) { i ->  
        ((Character.digit(s[i * 2], 16) shl 4) + Character.digit(s[i * 2 + 1], 16)).toByte()  
    }  
}  
  
val keyString = "6eba99bf3fac4c92a857b05cff433a39"  
var key = hexStringToByteArray(keyString)  
fun decrypt(ciphertext: ByteArray): String {  
    val cipher = Cipher.getInstance("AES/CBC/NoPadding")  
    val blockSize = cipher.blockSize  
  
    val iv = ciphertext.sliceArray(0 until blockSize)  
    val encryptedBytes = ciphertext.sliceArray(blockSize until ciphertext.size)  
  
    val secretKey = SecretKeySpec(key, "AES")  
    cipher.init(Cipher.DECRYPT_MODE, secretKey, IvParameterSpec(iv))  
  
    var decryptedBytes = cipher.doFinal(encryptedBytes)  
  
    val padding = decryptedBytes.last().toInt()  
    if (padding < 1 || padding > blockSize) return ""  
    for (i in decryptedBytes.size - padding until decryptedBytes.size) {  
        if (decryptedBytes[i].toInt() != padding) return ""  
    }  
    decryptedBytes = decryptedBytes.sliceArray(0 until decryptedBytes.size - padding)  
    return String(decryptedBytes)  
}
```
## Jsonplaceholder
has the most overcomplicated solution. 10/10 would waste time on it again
```python
@app.get("/get_flag")  
async def get_flag(request: Request):  
    try:  
        ip = request.headers['x-forwarded-for'].split(",")[-2].strip()  
    except Exception as e:  
        ip = request.client.host  
    if ip == '127.0.0.1':  
        return "FLAG"  
    return "NOT ALLOWED"
```
This is the endpoint we aim to reach. Given the nginx config:
```
...
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
...
```
I had initially tried setting the X-Forwarded-For header from my own requests to `127.0.0.1` in hopes nginx would then append its own headers and give us `127.0.0.1, <proxy ip>` but nothing seemed to work.
Next, the `a` endpoint:
```python
@app.post("/jsonplaceholder")  
async def jsonplaceholder(item: Item):  
    async with aiohttp.ClientSession() as session:  
        async with session.get(get_restapi(item)) as response: 
            return await response.json()
def get_restapi(item):  
    api = "https://jsonplaceholder.typicode.com"  
  
    pattern = re.compile(r'^[0-9a-zA-Z./_\-?]*$')  
    path = f"{item.cmd}/{item.val}"  
    if not pattern.fullmatch(path):  
        return f"{api}/posts/1"  
    return f"{api}{path}"
```
If we could somehow get the server to request `127.0.0.1/get_flag` and return that, we could obtain the flag
However, the `api` variable is prefixed in the url, making such calls impossible. In theory, a url like `<api url>@<Our url>/get_flag` could have worked, except the `@` character is sadly not allowed.  What if we had the `jsonplaceholder.typicode.com` as a subdomain? Perhaps from our own domain we could send a redirect to `127.0.0.1`. Thus, I obtained a domain from https://freedns.afraid.org/ and used https://redirect.pizza/ as the redirection service. Even then, the payload did not seem to work.
```json
{"cmd": ".mooo.com/get_flag?", "val":"0"}
```
After hours of brain racking, a finally stumbled across `start.sh` which contained:
```sh
#!/bin/sh
uvicorn main:app --host=0.0.0.0 --port=8000 --reload
```
Turns out, I had hadn't specified the port in the redirect. After all that, the payload finally returns `"CDDC24{Journ3ying_acr0ss_Hyrule}"`. 
> Additional comments: I am glad `response.json()` on a single string hadn't failed. Otherwise, all of my plans would have be foiled. 