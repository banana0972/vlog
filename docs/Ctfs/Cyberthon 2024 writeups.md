# One Click 🤑 One Dollar
![[Pasted image 20240508205341.png]]
This challenge contains a website where you click the button to earn money and can then buy items from the shop. Inspecting the source code, there is something interesting
```js
function buy(item) {
  ...
  txtlogging.innerText = `You bought ${item}`;
  // Perhaps there is some flag we can buy?
  if (item.includes("CTF"))
  
    txtlogging.innerText += ` and it reads: ${item.substring(0, 9)}\{${btoa(
      prices[item]
    )}\}`;
}
```
By placing a breakpoint here, we are able to edit `money` in the console, hence giving us infinite cash.
![[Pasted image 20240508205855.png]]
... And now the flag can be bought
![[Pasted image 20240508210446.png]]
## XORinfant 🍼
We are given a file which has been encrypted by a 10 byte long key, where the 1st byte encrypts the 1st , 11th,... bytes, the 2nd byte encrypts the 2nd, 12th,... bytes and so on
```python
KEY_LENGTH = 10  
XOR_KEY = secrets.token_bytes(KEY_LENGTH)
...
CIPHERTEXT = [FLAG[i] ^ XOR_KEY[i % KEY_LENGTH] for i in range(len(FLAG))]
```
Thankfully, we also happen to know the first 10 characters of the flag is `Cyberthon{`
```python
FLAG = "Cyberthon{" + bin(secrets.randbits(64))[2:].zfill(64) + "}"
FLAG = FLAG.encode()
```
Since xor is reversible, where `A^B=C` and `A^C=B`, we can simply xor the first 10 
bytes of the encrypted text and the known characters to get the key:
```python
with open("ciphertext.bin", 'rb') as file:  
    contents = file.read()  
keys = [0] * 10  
phrase = "Cyberthon{"  
for i in range(10):  
    cur = contents[i]  
    target = phrase[i]  
    keys[i] = cur ^ ord(target)  
flag = ""  
for i, char in enumerate(contents):  
    flag += chr(char ^ keys[i % 10])  
print(flag)
```
## Shark 🦈 Week
Opening the given pcap file in wireshark, there appears to be a lot of junk data coming from dynmap
![[Pasted image 20240508212815.png]]
By filtering out the images, we can get a cleaner log
`!http.request.uri contains ".webp" and !media`
Interestingly there are also some post requests to `login.php`
![[Pasted image 20240508213259.png]]Searching for more `.php` urls, we come across this
![[Pasted image 20240508213444.png]]
By following the HTTP stream, we have
`Set-Cookie: lastpartofflag=38e9fe9358ba1da4%7D; expires=Fri, 19 Apr 2024 14:02:53 GMT; Max-Age=3600; path=/` and a html page with a base64 encoded `<img>`.
Saving and opening the page in a browser would then reveal the final part of the flag
![[Pasted image 20240508213912.png]]
## 🕸️ Just Web Things (Post ctf)
> TODO: This challenge was revealed to by solved by a hash extension attack. It seems like a really cool concept as opposed to attempting to brute force 10^128 digits as I had contemplated. On the bright side I discovered a tool called hashcat lol