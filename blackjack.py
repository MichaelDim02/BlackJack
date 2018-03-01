# BlackJack v0.2 
# Password cracking software
# Michael C. Dim. - Thessaloniki, Central Macedonia, Greece
# Password cracking & penetration testing software
# You may not use this for illegal and/or malicious purposes

#    LIBRARIES    #
from __future__ import print_function
import hashlib
import time
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

	BlackJack v0.2 By MCD
""")
def options():
	print("""              __
        _..-''--'----_.
      ,''.-''| .---/ _`-._           Black Jack v0.2
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
# PASSWORD CRACKING #
def md5_crack():
	print("Hash: MD5")
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
		hashed_attempt = hashlib.md5(password).hexdigest()
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
def sha1_crack():
        print("Hash: SHA1")
        print("Dictionary: %s" % (str(dict)))
        print("Cracking...")
	start = time.time()
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
                        end = time.time()
                        time_elapsed = end - start;
			print("[!] Time elapsed: %d seconds" % (time_elapsed))
			print("[!] Session complete")
			exit()
		else:
			if verb == True:
				print("[%d] - FAILED ATTEMPT - %s" % (tries,password))
        print("[!] Session complete")
def sha256_crack():
        print("Hash: SHA256")
        print("Dictionary: %s" % (str(dict)))
        print("Cracking...")
	start = time.time()
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
                        end = time.time()
                        time_elapsed = end - start;
			print("[!] Time elapsed: %d seconds" % (time_elapsed))
			print("[!] Session complete")
			exit()
		else:
			if verb == True:
				print("[%d] - FAILED ATTEMPT - %s" % (tries,password))
        print("[!] Session complete")
def sha512_crack():
        print("Hash: SHA512")
        print("Dictionary: %s" % (str(dict)))
        print("Cracking...")
	start = time.time()
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
                        end = time.time()
                        time_elapsed = end - start;
			print("[!] Time elapsed: %d seconds" % (time_elapsed))
			print("[!] Session complete")
			exit()
		else:
			if verb == True:
				print("[%d] - FAILED ATTEMPT - %s" % (tries,password))
	print("[!] Session complete")
########################################################
# INFORMATION #
def information():
	logo()
	print("\nBlack Jack v0.2")
	print("Version: 0.2")
	print("License: GNU GPL v0.3 (2007)")
	print("Use for legal purposes only. The developer has no responsibility for")
	print("any damage caused by this program. By using this program users agree that")
	print("all the responsibility of any misuse of the software is theirs.")
	print("ASCII art by SSt (2006)")
	print("By MCD - Thessaloniki, Greece 2017-2018")

########################################################
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
