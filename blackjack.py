# BlackJack v0.4
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
version = "0.4"

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
`-._`-._`.`.;`.\  ,'  / /   github.com/MichaelDim02/BlackJack21
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
Bruteforce:
	--brf
	--md5 --sha1 --sha256 --sha512
	--digits 	Number of digits (Up to 10, 0 = all)
	--list (Number of list)
		1 = numbers
		2 = lowercase letters
		3 = lowercase letters, numbers
		4 = upper case
		5 = upper case, lower case
		6 = upper case, numbers
		7 = upper case, lower case, numbers

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
			hashed_attempt = hashlib.sha1(password).hexdigest()
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
# Bruteforce method #
def digit1():
	tries = 0
	start = time.time
        for item in list:
		tries = tries + 1
                password = item
                password = "".join(password)
		if md5_opt:
			hashed_attempt = hashlib.md5(password).hexdigest()
		elif sha1_opt:
			hashed_attempt = hashlib.sha1(password).hexdigest()
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
def digit2():
	tries = 0
	start = time.time()
        for item in plist:
                for item2 in plist:
			tries = tries + 1
                        password = item + item2
                        password = "".join(password)
			if md5_opt:
				hashed_attempt = hashlib.md5(password).hexdigest()
			elif sha1_opt:
				hashed_attempt = hashlib.sha1(password).hexdigest()
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
def digit3():
	tries = 0
	start = time.time()
        for item in plist:
                for item2 in plist:
                        for item3 in plist:
				tries = tries + 1
                                password = item + item2 + item3
                                password = "".join(password)
				if md5_opt:
					hashed_attempt = hashlib.md5(password).hexdigest()
				elif sha1_opt:
					hashed_attempt = hashlib.sha1(password).hexdigest()
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
def digit4():
	tries = 0
	start = time.time()
        for item in plist:
                for item2 in plist:
                        for item3 in plist:
                                for item4 in plist:
					tries = tries + 1
                                        password = item + item2 + item3 + item4
                                        password = "".join(password)
					if md5_opt:
						hashed_attempt = hashlib.md5(password).hexdigest()
					elif sha1_opt:
						hashed_attempt = hashlib.sha1(password).hexdigest()
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
def digit5():
	tries = 0
	start = time.time()
        for item in plist:
                for item2 in plist:
                        for item3 in plist:
                                for item4 in plist:
                                        for item5 in plist:
						tries = tries + 1
                                                password = item + item2 + item3 + item4 + item5
                                                password = "".join(password)
						if md5_opt:
							hashed_attempt = hashlib.md5(password).hexdigest()
						elif sha1_opt:
							hashed_attempt = hashlib.sha1(password).hexdigest()
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
def digit6():
	tries = 0
	start = time.time()
        for item in plist:
                for item2 in plist:
                        for item3 in plist:
                                for item4 in plist:
                                        for item5 in plist:
                                                for item6 in plist:
							tries = tries + 1
                                                        password = item + item2 + item3 + item4 + item5 + item6
                                                        password = "".join(password)
							if md5_opt:
								hashed_attempt = hashlib.md5(password).hexdigest()
							elif sha1_opt:
								hashed_attempt = hashlib.sha1(password).hexdigest()
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
def digit7():
	tries = 0
	start = time.time()
        for item in plist:
                for item2 in plist:
                        for item3 in plist:
                                for item4 in plist:
                                        for item5 in plist:
                                                for item6 in plist:
							for item7 in plist:
								tries = tries + 1
                                                        	password = item + item2 + item3 + item4 + item5 + item6 + item7
                                                        	password = "".join(password)
								if md5_opt:
									hashed_attempt = hashlib.md5(password).hexdigest()
								elif sha1_opt:
									hashed_attempt = hashlib.sha1(password).hexdigest()
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
def digit8():
	tries = 0
	start = time.time()
        for item in plist:
                for item2 in plist:
                        for item3 in plist:
                                for item4 in plist:
                                        for item5 in plist:
                                                for item6 in plist:
                                                        for item7 in plist:
                                                                for item8 in plist:
									tries = tries + 1
                                                                        password = item + item2 + item3 + item4 + item5 + item6 + item7 + item8
                                                                        password = "".join(password)
									if md5_opt:
										hashed_attempt = hashlib.md5(password).hexdigest()
									elif sha1_opt:
										hashed_attempt = hashlib.sha1(password).hexdigest()
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
def digit9():
	tries = 0
	start = time.time()
        for item in plist:
                for item2 in plist:
                        for item3 in plist:
                                for item4 in plist:
                                        for item5 in plist:
                                                for item6 in plist:
                                                        for item7 in plist:
                                                                for item8 in plist:
                                                                        for item9 in plist:
										tries = tries + 1
                                                                                password = item+item2+item3+item4+item5+item6+item7+item8
                                                                                password = "".join(password)
										if md5_opt:
											hashed_attempt = hashlib.md5(password).hexdigest()
										elif sha1_opt:
											hashed_attempt = hashlib.sha1(password).hexdigest()
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
def digit10():
	tries = 0
	start = time.time()
        for item in plist:
                for item2 in plist:
                        for item3 in plist:
                                for item4 in plist:
                                        for item5 in plist:
                                                for item6 in plist:
                                                        for item7 in plist:
                                                                for item8 in plist:
                                                                        for item9 in plist:
                                                                                for item10 in plist:
											tries = tries + 1
                                                                                        password = item+item2+item3+item4+item5+item6+item7+item8+item9+item10
                                                                                        password = "".join(password)
										if md5_opt:
											hashed_attempt = hashlib.md5(password).hexdigest()
										elif sha1_opt:
											hashed_attempt = hashlib.sha1(password).hexdigest()
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
# Bruteforce #
parser.add_argument("--brf", help="Bruteforce mode", action="store_true")
parser.add_argument("--digits", help="Digits (Up to 10, 0 = all)")
parser.add_argument("--list", help="List of characters")
# hashes vars #
args = parser.parse_args()
md5_opt = args.md5
sha1_opt = args.sha1
sha256_opt = args.sha256
sha512_opt = args.sha512
# bruteforce #
brf = args.brf
dig = args.digits
lst = args.list
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
	if brf:
		if lst == "1":
			plist = ['0','1','2','3','4','5','6','7','8','9']
		elif lst == "2":
			plist= ['a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z']
		elif lst == "3":
			plist = ['a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','0','1','2','3','4','5','6','7','8','9']
		elif lst == "4":
			plist = ['A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z']
		elif lst == "5":
			plist = ['A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z']
		elif lst == "6":
			plist = ['A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','0','1','2','3','4','5','6','7','8','9']
		elif lst == "7":
			plist = ['A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','0','1','2','3','4','5','6','7','8','9']
		else:
			print("[+] List not found")
			exit()
		if dig == "0":
			digit1()
			digit2()
			digit3()
			digit4()
			digit5()
			digit6()
			digit7()
			digit8()
			digit9()
			digit10()
		elif dig == "1":
			digit1()
		elif dig == "2":
			digit2()
		elif dig == "3":
			digit3()
		elif dig == "4":
			digit4()
		elif dig == "5":
			digit5()
		elif dig == "6":
			digit6()
		elif dig == "7":
			digit7()
		elif dig == "8":
			digit8()
		elif dig == "9":
			digit9()
		elif dig == "10":
			digit10()
		else:
			print("[!] Blackjack supports digits 0-10 (0 = all)")
	else:
		crack()
else:
	options()
