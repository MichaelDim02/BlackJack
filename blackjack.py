import hashlib
import colorama
import argparse
#    INTERFACE    #
def logo():
	print("""
______ _            _      ___            _
| ___ \ |          | |    |_  |          | |
| |_/ / | __ _  ___| | __   | | __ _  ___| | __
| ___ \ |/ _` |/ __| |/ /   | |/ _` |/ __| |/ /
| |_/ / | (_| | (__|   </\__/ / (_| | (__|   <
\____/|_|\__,_|\___|_|\_\____/ \__,_|\___|_|\_\\

""")
def options():
	print("""              __
        _..-''--'----_.
      ,''.-''| .---/ _`-._           Black Jack v0.1
    ,' \ \  ;| | ,/ / `-._`-.
  ,' ,',\ \( | |// /,-._  / /     Password Cracker
  ;.`. `,\ \`| |/ / |   )/ /           By Michael C Dim.
 / /`_`.\_\ \| /_.-.'-''/ /
/ /_|_:.`. \ |;'`..')  / /          Black Jack 21
`-._`-._`.`.;`.\  ,'  / /            2017 - 2018
    `-._`.`/    ,'-._/ /
      : `-/     \`-.._/  Hashes included:
      |  :      ;._ (		     --md5
      :  |      \  ` \		     --sha1
       \         \   |		     --sha256
        :        :   ;               --sha512
        |           /
        ;         ,'     Arguments:
       /         /                   -p	--pswd  Hashed Pass
      /         /                    -d --dict  Dictionary
               / SSt		     -v --verb  Verbose opt
				     -i --info  Information

Usage: python blackjack.py --md5 -p [HASH] -d [DICT] -v
""")
########################################################
def md5_crack():
	tries = 0
	try:
		file = open(dict, "r").read().split('\n')
	except:
		print("File could not be found")
		exit()
	for password in file:
		tries = tries + 1
		hashed_attempt = hashlib.md5(password).hexdigest()
		if hashed_attempt == hash:
			print("\n[%d] - PASSWORD FOUND - %s\n" % (tries,password))
			exit()
		else:
			if verb == True:
				print("[%d] - FAILED ATTEMPT - %s" % (tries,password))
def sha1_crack():
	tries = 0
	try:
		file = open(dict, "r").read().split('\n')
	except:
		print("File could not be found")
		exit()
	for password in file:
		tries = tries + 1
		hashed_attempt = hashlib.sha1(password).hexdigest()
		if hashed_attempt == hash:
			print("\n[%d] - PASSWORD FOUND - %s\n" % (tries,password))
			exit()
		else:
			if verb:
				print("[%d] - FAILED ATTEMPT - %s" % (tries,password))

def sha256_crack():
	tries = 0
	try:
		file = open(dict, "r").read().split('\n')
	except:
		print("File could not be found")
		exit()
	for password in file:
		tries = tries + 1
		hashed_attempt = hashlib.sha256(password).hexdigest()
		if hashed_attempt == hash:
			print("\n[%d] - PASSWORD FOUND - %s\n" % (tries,password))
			exit()
		else:
			if verb == True:
				print("[%d] - FAILED ATTEMPT - %s" % (tries,password))
def sha512_crack():
	tries = 0
	try:
		file = open(dict, "r").read().split('\n')
	except:
		print("File could not be found")
		exit()
	for password in file:
		tries = tries + 1
		hashed_attempt = hashlib.sha512(password).hexdigest()
		if hashed_attempt == hash:
			print("\n[%d] - PASSWORD FOUND - %s\n" % (tries,password))
			exit()
		else:
			if verb == True:
				print("[%d] - FAILED ATTEMPT - %s" % (tries,password))
########################################################
def information():
	print("\nBlack Jack v0.1")
	print("\nVersion: 0.1")
	print("License: GNU GPL v0.3 (2007)")
	print("Use for legal purposes only. The developer has no responsibility for")
	print("any damage caused by this program. By using this program users agree that")
	print("all the responsibility of any misuse of the software is theirs.")
	print("ASCII art by SSt (2006)")
	print("By MCD - Thessaloniki, Greece 2017-2017")
	print("E-mail: anivsante2@gmail.com")
########################################################
parser = argparse.ArgumentParser()
# Hashes #
parser.add_argument("--md5", action="store_true")
parser.add_argument("--sha1", action="store_true")
parser.add_argument("--sha256", action="store_true")
parser.add_argument("--sha512", action="store_true")
# Options & Arguments #
parser.add_argument("-p", "--pswd", help="Hashed Pass")
parser.add_argument("-d", "--dict", help="Dictionary")
parser.add_argument("-v", "--verb", action="store_true", help="Verbose opt")
parser.add_argument("-i", "--info", action="store_true", help="Information")
# hashes vars #
args = parser.parse_args()
md5_opt = args.md5
sha1_opt = args.sha1
sha256_opt = args.sha256
sha512_opt = args.sha512
# opts vars #
hash = args.pswd
dict = args.dict
verb = args.verb
info = args.info
if info == True:
	logo()
	information()
	exit()
elif md5_opt == True:
	logo()
	md5_crack()
elif sha1_opt == True:
	logo()
	sha1_crack()
elif sha256_opt == True:
	logo()
	sha256_crack()
elif sha512_opt == True:
	logo()
	sha512_crack()
else:
	logo()
	options()
