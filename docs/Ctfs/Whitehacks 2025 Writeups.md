Solves: Travel back to a time gone by(web), dirbusted (web), Live fun(web), traversal(web)
# Travel back to a time gone by
We are given a single static page with no extra forms/requests/js. When inspecting the html of the page, we can find a mysterious hidden image.
![[Pasted image 20250312224800.png]]
Opening it, the flag is shown
![[Pasted image 20250312224853.png]]
> Pro-tip for future "find the flag" challenges: Set burp to show images too in case the flags are hidden in the image/it's response headers

`WH2025{ilovechinatownandwannavisititoneday}`
# Dirbusted
#langs/python 
As hinted by the challenge name, we probably should use the dirbuster tool on the website(I wasn't very sure about this as I thought the ctf forbid scanners/brute force).
Initially choosing to dirbust both files and directories,  I realized the scan would take way too long. Hence, I went back to the website to see if there was anything noteworthy. As seen from the headers, the server running this site is SimpleHttp, the built-in http module in python.
![[Pasted image 20250312231601.png]]
A quick [google search](https://www.digitalocean.com/community/tutorials/python-simplehttpserver-http-server) shows that there seems to be some sort of built-in directory listing , unless an `index.html` or `index.htm` file is found, in which case the latter is displayed instead(The directory listing still works for other directories). This will simplify the scanning process as we would only need to find a valid directory path to be able to view all its contents. Running dirbuster to only find directories this time, we find the `hidden` folder
![[Pasted image 20250312233232.png]]
From there, we see it holds the flag
![[Pasted image 20250312233348.png]]
`WH2025{DIBUSTYYYYYYY!!!!!}`
> For future reference: Behavior of the SimpleRequestHandler can be further inspected. Perhaps there is a way to trick it to display the dir listing even if the index files exist
> https://github.com/python/cpython/blob/main/Lib/http/server.py#L841

# Live fun
#langs/php
We are given a suspiciously empty page with not much information
![[Pasted image 20250317192608.png]]
Most of the text seems unimportant, except the underlined <u>page?</u> which stands out. Come to think of it, it does seem to be hinting for us to try that query parameter, so let's try that.
![[Pasted image 20250317193011.png]]
How interesting. It seems the sever is taking the query parameter and trying to include a file into the php code directly. I first tried guessing random filenames like `flag.txt` but didn't get any results
![[Pasted image 20250317193146.png]]
To ensure the LFI was even working, I tried the common paths to text, such as `/etc/passwd`
![[Pasted image 20250317193305.png]]
Oh. There is the flag I guess???
`WH2025{LEAVEMEALONEpls}`
# Traversal
#langs/python 
We are greeted with a website with 2 links to `memo_1.txt` and `memo_2.txt`
![[Pasted image 20250317204034.png]]
Visiting them, we see the server seems to send the file specified by the `file` query parameter. 
![[Pasted image 20250317204405.png]]
Additionally, memo 2 mentions something about path traversal being fixed.
![[Pasted image 20250317204335.png]]
Let's try it out either way. Trying to find the app's source code, I blindly tried
`http://challenges.whitehats-ctf.com:8009/download?file=../app.py`, only for it to get denied.
![[Pasted image 20250317204521.png]]
it seems traversing up a directory is blocked, as any path containing `..` gets rejected
![[Pasted image 20250317204625.png]]
If relative paths don't work, how about absolute paths? Once again trying the common file paths, I checked out `/etc/passwd` and successfully downloaded the file, meaning absolute paths worked.
![[Pasted image 20250317204927.png]]
Here, we see the `john` user and his home directory `/home/john`, which *might* be where the app might be running at. I blindly tried guessing various paths to find `app.py` such as `/home/john/app.py`, `/home/john/app/app.py`, `/home/john/main.py`... only to realize I probably would never manage to guess the location of the app
### The cheese
Instead of trying to brute force the possible paths, I instead turned my attention to the special linux directories, namely the [proc filesystem](https://docs.kernel.org/filesystems/proc.html#process-specific-subdirectories). Inside it contains directories that are mapped to processes in the form `/proc/<pid>`, and contains fancy information about the current running processes, such as environment variables and the command line args used to run the program. 

There is also the `cwd` subdirectory, which links to the working directory in which a process was started in. In addition to accessing the corresponding directories by pid, there is also the `/proc/self` directory, which links to the proc data directory of the process accessing it. By accessing `/proc/self/cwd`, we effectively get to the working directory of the app without knowing it's path.
From there, we are able to get the source code of the app, revealing the flag hardcoded in.
![[Pasted image 20250317210439.png]]
`WH2025{wh0a_d1Rec7oRy_tR4v3r$A1_1s_c00L}`


# Post ctf lessons
## Flawless login page
#langs/python , #langs/sql 
TODO Sql oracle attack didn't work???? Put the various payloads I tried here
```python
def fetch(pw):
    # body = {"username": "Jacob", "password": f"' or password like '{pw}%';--"}
    # body = {"username": "Jacob", "password": f"' or password glob '{pw}*';--"}
    # body = {"username": "Jacob", "password": f"' or substr(password, 1, {len(pw)}) glob '{pw}';--"} # idk case-sensitive search
    body = {"username": "Jacob", "password": f"' or instr(password, '{pw}') = 1;--"} # Works best? Just remember to remove forbidden chars like '
```
