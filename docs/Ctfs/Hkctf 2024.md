Solves: New free lunch(Web), Webpage to pdf(1) (Web, assisted by guide), Mystiz's Mini CTF(1) (Web), # Mystiz's Mini CTF(2) (Web), Void (Web rev)
# New free lunch
Score and hash are both generated client side, just modify it to a large number.
Set debugger breakpoint before computing hash, set score in console
# Void
Same trick, you can set a debug breakpoint and observe the payload being reconstructed from the whitespaces step by step. No extra steps as flag checker is not obfuscated
![[Pasted image 20241114161942.png]]
# Webpage to pdf(1)
> The writeup will be more of a step-by-step solution than an actual personal writeup

This challenge has an unsafe function which allows arbitrary flags to be specified
execute_command.py:
```python
def execute_command(command):  
	args = shlex.split(command)
    try:  
        result = subprocess.run(  
            args,  
            stdout=subprocess.PIPE,  
            stderr=subprocess.PIPE,  
            text=True,  
            check=True  # Raises CalledProcessError for non-zero exit codes  
        )  
        return result.stdout, result.stderr, result.returncode 
    except subprocess.CalledProcessError as e:  
        return e.stdout, e.stderr, e.returncode
```
main.py:
```python
@app.route('/process', methods=['POST'])  
def process_url():  
    # Get the session ID of the user  
    session_id = request.cookies.get('session_id')  
    html_file = f"{session_id}.html" # This has to be a valid filepath  
    pdf_file = f"{session_id}.pdf"    
    response = requests.get(url)  
    response.raise_for_status()  
    with open(html_file, 'w') as file:  
        file.write(response.text)  
    # Make PDF  
    stdout, stderr, returncode = execute_command(f'wkhtmltopdf {html_file} {pdf_file}')  
    print(stdout, stderr, returncode)  
```
Hence, we are able to pass cli flags through the `session_id`. Unfortunately, we can't utilize command substitution as the commands are not run from bash. Searching for cve's related to wkhtmltopdf, we find a lfi vulnerability for an old version of wkhtmltopdf: https://security.snyk.io/vuln/SNYK-UNMANAGED-WKHTMLTOPDFWKHTMLTOPDF-2981043. In the github issue, it is mentioned that the `--enable-local-file-access` flag is now required to access local files: https://github.com/wkhtmltopdf/wkhtmltopdf/issues/4536#issuecomment-643019765. Therefore, we first send a request to convert a html page with the payload under the session_id `a` to get a saved html file `a.html`.
```html
...
<iframe src="file:///flag.txt">
...
```
Then, we send another request under the session id `--enable-local-file-access a.html`. The server first saves the html page with the mangled session id, then runs the command `wkhtmltopdf --enable-local-file-access a.html --enable-local-file-access a.pdf`, hence allowing the local file to be read this time. From there, we visit `a.pdf` to get the flag.
> TODO: I tried using ngrok to host the files but it didn't work for some reason. I ended up  using https://jsbin.com, which was what the guide used.
# Mystiz's Mini CTF(2)
Both 1 and 2 use the same source code.
This challenge involves a website which imitates a ctf platform. Users can register, login, submit flags and view the scoreboard. As part 2 had more solves, I decided to try it first.
In both parts, the flags were hidden within challenges on that platform, with the first flag being a challenge that was solved by a fake player and the second being hidden in the description of an unreleased challenge
```python
def upgrade():  
	...
    ADMIN_PASSWORD = os.urandom(33).hex()  
    PLAYER_PASSWORD = os.urandom(3).hex()  
  
    FLAG_1 = os.environ.get('FLAG_1', 'flag{***REDACTED1***}') 
    FLAG_2 = os.environ.get('FLAG_2', 'flag{***REDACTED2***}')  
    RELEASE_TIME_NOW    = date.today()  
    RELEASE_TIME_BACKUP = date.today() + timedelta(days=365)  
  
    db.session.add(User(id=1, username='admin', is_admin=True, score=0, password=ADMIN_PASSWORD))  
    db.session.add(User(id=2, username='player', is_admin=False, score=500, password=PLAYER_PASSWORD, last_solved_at=datetime.fromisoformat('2024-05-11T03:05:00')))  
    db.session.add(Challenge(id=1, title='Hack this site!', description=f'I was told that there is <a href="/" target="_blank">an unbreakable CTF platform</a>. Can you break it?', category=Category.WEB, flag=FLAG_1, score=500, solves=1, released_at=RELEASE_TIME_NOW))  
	...
    db.session.add(Challenge(id=7, title='A placeholder challenge', description=f'Many players complained that the CTF is too guessy. We heard you. As an apology, we will give you a free flag. Enjoy - <code>{FLAG_2}</code>.', category=Category.MISC, flag=FLAG_2, score=500, solves=0, released_at=RELEASE_TIME_BACKUP))  
    
    db.session.add(Attempt(challenge_id=1, user_id=2, flag=FLAG_1, is_correct=True, submitted_at=RELEASE_TIME_NOW))  
    db.session.commit()
```
Checking our `/challenges`, you can see the misc challenge is nowhere to be seen
![[Pasted image 20241114170110.png]]
We will somehow need a way to view that challenge. Looking at the templates of the challenge, we see there is an admin dashboard:
![[Pasted image 20241114170244.png]]
From the code, it seems like that dashboard allows us to view challenges:
```html
<script>  
  async function listChallenges() {  
    const listChallengesResponse = await fetch('/api/admin/challenges')  
    const { challenges } = await listChallengesResponse.json() 
    ...
  }
  listChallenges()  
  </script>
```
Checking out that route on the flask end, we can see this:
```python
@route.route('/', methods=[HTTPMethod.GET])  
@login_required  
def list_challenges():  
    if not current_user.is_admin:  
        return jsonify({'error': 'not an admin'}), HTTPStatus.FORBIDDEN  
    challenges = Challenge.query.all()  
  
    return jsonify({  
        'challenges': [challenge.admin_marshal() for challenge in challenges]  
    }), HTTPStatus.OK
```
The admin api seems to not perform any filtering, as opposed to the user api:
challenge.py:
```python
class _QueryViewProperty:  
    def __get__(self, obj, cls):  
        return cls.query.filter(cls.released_at <= datetime.now())  
  
class Challenge(db.Model):  
	...
    query_view = _QueryViewProperty()
```
views/\_\_init\_\_.py:
```python
class GroupAPI(MethodView):  
	...
    def get(self):  
        items = self.model.query_view.all()
	...
  
def register_api(app, model, name):  
    group = GroupAPI.as_view(f'{name}_group', model)  
    app.add_url_rule(f'/api/{name}/', view_func=group)  
      
def init_app(app):  
	...
    app.register_blueprint(challenges.route, url_prefix='/api/challenges')  
	...
	register_api(app, Challenge, 'challenges')
	...
```
Hence, we should try to find a way to get admin to view the hidden challenge.
The admin password is too long to be brute force, especially with a 2/min ratelimit on logging in. What if we find a way to give ourselves admin?
From the `/register` endpoint:
```python
@route.route('/register/', methods=[HTTPMethod.POST])  
def register_submit():  
    user = User()  
    UserForm = model_form(User)  
  
    form = UserForm(request.form, obj=user)
  
    if not form.validate():  
        flash('Invalid input', 'warning')  
        return redirect(url_for('pages.register'))  
  
    form.populate_obj(user)  
  
    user_with_same_username = User.query_view.filter_by(username=user.username).first()  
    if user_with_same_username is not None:  
        flash('User with the same username exists.', 'warning')  
        return redirect(url_for('pages.register'))  
  
    db.session.add(user)  
    db.session.commit()  
  
    login_user(user)  
    return redirect(url_for('pages.homepage'))
```
This code seems to populate a user entry based on whatever the form specifies, then add the entry to the database. Indeed, we can see the form input names and the fields of the models correspond:
```html
<form method="POST" action="/register/">  
	...
    <input type="text" name="username" class="form-control" placeholder="Username" autofocus>  
	...
	<input type="password" name="password" class="form-control" placeholder="Password"> 
	...
</form>
```
```python
class User(db.Model):  
    id = db.Column(db.Integer, primary_key=True)  
    username = db.Column(db.String, nullable=False)  
    is_admin = db.Column(db.Boolean, default=False)  
    password = db.Column(db.String, nullable=False)  
    score = db.Column(db.Integer, default=0)  
    last_solved_at = db.Column(db.DateTime)
```
There seems to be no validation of the form we submit, so what would happen if we added an extra form input for `is_admin`?
![[Pasted image 20241114173154.png]]Just like that, we are able to access the admin dashboard and get the flag
![[Pasted image 20241114173228.png]]
![[Pasted image 20241114173406.png]]
`hkcert24{y0u_c4n_wr1t3_unsp3c1f13d_4t7r1bu73s_t0_th3_us3r_m0d3l}`
# Mystiz's Mini CTF(2)
The first flag is harder. Flags for the challenges are all hashed 
challenge.py:
```python
@event.listens_for(Challenge.flag, 'set', retval=True)  
def hash_challenge_flag(target, value, oldvalue, initiator):  
    if value != oldvalue:  
        return compute_hash(value)  
    return value

  
def compute_hash(password, salt=None):  
	if salt is None:  
        salt = os.urandom(4).hex()  
    return salt + '.' + hashlib.sha256(f'{salt}/{password}'.encode()).hexdigest()
```
and no api will include even the hashed flag as part of their response. However, when searching around, we see that attempts *do* store unhashed flags attempts of every challenge submission:
```python
class Attempt(db.Model):  
    id = db.Column(db.Integer, primary_key=True)  
    challenge_id = db.Column(db.ForeignKey('challenge.id'), nullable=False)  
    user_id = db.Column(db.ForeignKey('user.id'), nullable=False)  
    flag = db.Column(db.String, nullable=False)  
    is_correct = db.Column(db.Boolean, nullable=False)  
    submitted_at = db.Column(db.DateTime, nullable=False)  
  
    query_view = _QueryViewProperty()  
  
    def marshal(self):  
        return {  
            'id': self.id,  
            'challenge_id': self.challenge_id,  
            'user_id': self.user_id,  
            'is_correct': self.is_correct,  
        }
```
And from the migration script:
```python
db.session.add(Attempt(challenge_id=1, user_id=2, flag=FLAG_1, is_correct=True, submitted_at=RELEASE_TIME_NOW))
```
As seen, `marshal()` does not include any information about the flag, so we need to extract it another way. Looking back at the webpage, we see something interesting about GroupApi:
```python
class GroupAPI(MethodView):  
	...
	def get(self):
        group = request.args.get('group')  
        # If group exists and does not start with _ (Probs to hide private properties) and it exists in the Model requested  
        if group is not None and not group.startswith('_') and group in dir(self.model):  
            grouped_items = collections.defaultdict(list)  
            # For each record  
            for item in items:  
                # Id is the value of the property?  
                id = str(item.__getattribute__(group))  
                grouped_items[id].append(item.marshal())  
            return jsonify({self.name_plural: grouped_items}), 200  
  
        return jsonify({self.name_plural: [item.marshal() for item in items]}), 200
```
It seems to be able to accept a `group` query string which will group all records received by the `group` specified. Using that, we can extract fields that are not returned by `marshal()`
As a POC, we can extract flags from our own solves:
![[Pasted image 20241114183755.png]]
In order to obtain the attempts by the `player`, we will need to be able to login to their account. The password for the player is suspiciously short compared to the admin password, so we could try cracking it
```python
ADMIN_PASSWORD = os.urandom(33).hex()  
# TODO Password is suspiciously short  
PLAYER_PASSWORD = os.urandom(3).hex()
```
Using the previous method, we can obtain the hashed password along with its salt
![[Pasted image 20241114184139.png]]
From there, we plop the hash into hashcat to crack it
hashfile.txt:
`744c75c952ef0b49cdf77383a030795ff27ad54f20af8c71e6e9d705e5abfb94:77364c85/`
```bash
hashcat -m 1420 -a 3 -o out.txt hashfile.txt ?h?h?h?h?h?h
```
(Hashes differ because they are from another attempt)
With the password, we can now login to the player account and employ the same trick to get the flag. 
![[Pasted image 20241114185625.png]]
`hkcert24{y0u_c4n_9r0up_unsp3c1f13d_4t7r1bu73s_fr0m_th3_4tt3mp7_m0d3l}`
