Solves: S.K.I.B.I.D.I. (web), EasyXSSChallenge(web),  S.K.I.B.I.D.I. Revenge(web)
I was able to first blood all 3 challenges and was the reason  S.K.I.B.I.D.I. got a revenge challenge :D
## S.K.I.B.I.D.I.
#langs/python
### Code review
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