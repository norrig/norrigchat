from flask import Flask, render_template, make_response, request, redirect, url_for, jsonify
from flask_socketio import SocketIO, send
import bcrypt, jwt, time, random
from cryptography.fernet import Fernet
import json
app = Flask(__name__)
app.config['SECRET'] = 	"secret!123"

socketio = SocketIO(app, cors_allowed_origins="*")


HOST_NAME = "localhost"
HOST_PORT = 5000
JWT_KEY = "secret!123" 
JWT_ISS = "norrig-sec"
JWT_ALGO = "HS512"

username = "not logged in yet"
## kode 12345 ## kode 54321 ## kode 112233
USERS = {
	"user1@eaaa.dk" : b'$2b$12$3kcEc8qxnrHGCBHM8Bh0V.gWEFpsxpsxbkCfmk4BDcjBkGsVLut8i', 
	"norrig@live.dk" : b'$2b$12$qlY8FPrEeUtwgWNmeH2KoeBLOm08HRDnOf2jTPcYb1CB6dpx9FV1O', 
	"test@hej.dk" : b'$2b$12$pPeVbhEEbdvFn39gjsJrA.RKEqgmeaTxrd34hIdnxZj.JDBJOXZrO' 
}

def jwtSign(email):
	random = "".join(random.choice("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz~!@#$%^_-") for i in range(24))
	now = int(time.time())
	return jwt.encode({
		"iat" : now, "nbf" : now, "exp" : now + 4200, "jti" : random, "iss" : JWT_ISS, 
		"data" : { "email" : email }
	}, JWT_KEY, algorithm=JWT_ALGO)

def jwtVerify(cookies):
	try:
		token = cookies.get("JWT")
		print("debug token:")
		print(token)
		decoded = jwt.decode(token, JWT_KEY, algorithms=[JWT_ALGO])
		return True
	except:
		return False

def encrypt_msg(userName, userMessage, userkey):
	print("encrypting with")
	print(userkey)
	fernet = Fernet(userkey)
	encMessage = fernet.encrypt(userMessage.encode())
	print("Krypteret besked "+str(encMessage))
	msg = userName+": "+str(encMessage)+": "+"lol" ##Vi putter det hele tilbage i rigtigt format
	print(msg)
	print("type debug")
	print(type(msg))
	msg = json.dumps(msg)
	print(type(msg))
	return msg


@app.route("/decrypt_msg_route", methods=['GET', 'POST'])
def decrypt_msg():
	if request.method == 'POST':
		form = request.get_json()
		print(form)
		#form = json.load(form)
	if len(form) > 2:
		#E-aiNIDAVS2IK_E1WRXQ0zGgnUUI34zoZydHK962y2k= example nøgle
		print("!!!decrypting") 
		key = form[3]
		msg = form[1].strip()
		msg = msg[1:]
		msg = msg.replace("'", "")
		msg = bytes(msg, encoding="utf-8")
		print("format check")
		print(msg)
		print(type(msg))
		print("Using key:")
		print(key)
		try:
				fernet = Fernet(key)
				decryptedMsg = fernet.decrypt(msg)
				print("Plaintext:")
				print(decryptedMsg)
				decryptedMsg = decryptedMsg.decode("utf-8")
				form[1] = decryptedMsg
				print("full form:")
				print(jsonify(form))				
		except:
				print("wrong key tihi")
				form = ['Unknown', 'Encrypted Message', 'EEE']	

		return jsonify(form)
	return	

@socketio.on('message')
def handle_message(message):
	krypteret = 0
	print("Received message: " + message)
	print(type(message))
	
	try:
		messageSplit = message.split(':')
		print("LEEEN")
		print(len(messageSplit))
	except: 
		print("æøå fejl")		
	try:
		messageSplit = message.split(':')
		userName = messageSplit[0]
		userMessage = messageSplit[1]
		userkey = messageSplit[2]
		krypteret = 1
		print("user key:")
		print(userkey[2])
		print("Skal krypteres")
	except:
		print("Ikke krypteret")	
		krypteret = 0
	if message != "User connected!":
		if krypteret == 0:
			#send den ud
			print("sender normal besked")
			send(message, broadcast = True)
		if krypteret == 1:
			encrypted_msg = encrypt_msg(userName, userMessage, userkey)
			print("sender krypteret besked")
			send(encrypted_msg, broadcast = True)
			
		

@app.route("/login")
def login():

	if jwtVerify(request.cookies):
		return redirect(url_for("admin"))
	else:
		return render_template("login.html")	

@app.route("/lin", methods=["POST"])
def lin():
	data = dict(request.form)
	print(data)
	valid = data["email"] in USERS
	global username

	password = data["password"]
	print("debug pw:")
	print(password)	

	if valid:
		valid = bcrypt.checkpw(data["password"].encode("utf-8"), USERS[data["email"]]) #valid?
	msg = "ok login" if valid else "forkert login"
	res = make_response(msg, 200)
	if valid:
		res.set_cookie("JWT", jwtSign(data["email"]))
		print("Godkendt login")
		username = data["email"]
		res.set_cookie('username', username) #username må gerne gemmes i plaintext så vi kan læse det senere
		print("username= "+str(username))
	return res   	

@app.route("/lout", methods=["POST", "GET"]) #behøver nok kun POST
def lout():
	print("Sletter cookies")
	res = make_response(redirect(url_for('default_page')))
	res.delete_cookie("JWT")
	print("Bruger har logget ud")
	return res


@app.route('/frontend')
def default_page():
	print("default page funktion")
	if jwtVerify(request.cookies):
		print("velkommen")
		return render_template("frontend.html", email=username)
	else:
		print("forkert pw / ikke logget ind")
		return render_template("login.html")	
	

#primær route
@app.route('/')
def admin():
	global username
	username = request.cookies.get('username')
	print("fra cookie: "+str(username))
	print("admin page funktion")

	if jwtVerify(request.cookies):
		print("front req")
		return render_template("frontend.html", email=username)
	else:
		return redirect(url_for("login"))	



#app.jinja_env.globals.update(decrypt_msg=decrypt_msg) 
	
if __name__ == "__main__":
	socketio.run(app, host="localhost")
