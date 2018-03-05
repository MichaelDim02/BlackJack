# BlackJack v0.3
# Password cracking software
# Michael C. Dim. - Thessaloniki, Central Macedonia, Greece
# Password cracking & penetration testing software
# You may not use this for illegal and/or malicious purposes
# License:
# GNU GPL v0.3

#    LIBRARIES    #
from __future__ import print_function
import hashlib
import time
import argparse

#     VERSION     #
version = "0.3"

#    INTERFACE    #
def logo():
	print("""______ _            _      ___            _
| ___ \ |          | |    |_  |          | |
| |_/ / | __ _  ___| | __   | | __ _  ___| | __
| ___ \ |/ _` |/ __| |/ /   | |/ _` |/ __| |/ /
| |_/ / | (_| | (__|   </\__/ / (_| | (__|   <
\____/|_|\__,_|\___|_|\_\____/ \__,_|\___|_|\_\\

	BlackJack v%s By MCD 2017-2018""" % version)

def options():
	print("""              __
        _..-''--'----_.
      ,''.-''| .---/ _`-._           Black Jack v%s
    ,' \ \  ;| | ,/ / `-._`-.
  ,' ,',\ \( | |// /,-._  / /     Password Cracker
  ;.`. `,\ \`| |/ / |   )/ /           By Michael C Dim.
 / /`_`.\_\ \| /_.-.'-''/ /
/ /_|_:.`. \ |;'`..')  / /          BlackJack 21
`-._`-._`.`.;`.\  ,'  / /   github.com/MichaelDim/BlackJack21
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

Usage: python blackjack.py --md5 -p [HASH] -d [DICT] -v""" % version)

# PASSWORD CRACKING #
def crack():
	if md5_opt:
		print("Hash: MD5")
	elif sha1_opt:
		print("Hash: SHA1")
	elif sha256_opt:
		print("Hash: SHA256")
	elif sha512_opt:
		print("Hash: SHA512")
	print("Dictionary: %s" % (str(dict)))
	print("Cracking..")
	start = time.time()
	tries = 0
	try:
		file = open(dict, "r").read().split('\n')
	except:
		print("File could not be found")
		exit()
	for password in file:
		tries = tries + 1
		if md5_opt:
			hashed_attempt = hashlib.md5(password).hexdigest()
		elif sha1_opt:
			hashed_attempt = hashlib.sha1(passowrd).hexdigest()
		elif sha256_opt:
			hashed_attempt = hashlib.sha256(password).hexdigest()
		elif sha512_opt:
			hashed_attempt = hashlib.sha512(password).hexdigest()
		if hashed_attempt == hash:
			print("\n[%d] - PASSWORD FOUND - %s\n" % (tries,password))
			end = time.time()
			time_elapsed = end - start;
			print("[!] Time elapsed: %d seconds" % (time_elapsed))
			print("[!] Session complete")
			exit()
		else:
			if verb == True:
				print("[%d] - FAILED ATTEMPT - %s" % (tries,password))
	print("[!] Session complete")

# INFORMATION #
def information():
	logo()
	print("\nBlack Jack %s" % version)
	print("Version: %s" % version)
	print("License: GNU GPL v0.3 (2007)")
	print("Use for legal purposes only. The developer has no responsibility for")
	print("any damage caused by this program. By using this program users agree that")
	print("all the responsibility of any misuse of the software is theirs.")
	print("ASCII art by SSt (2006)")
	print("By MCD - Thessaloniki, Greece 2017-2018")

# ARGUMENT PARSING #
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
logo()
if info == True:
	information()
	exit()
elif md5_opt or sha1_opt or sha256_opt or sha512_opt:
	crack()
else:
	options()
