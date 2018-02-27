from __future__ import print_function
import hashlib

#  hash.py
#  Made for Blackjack & Blackjack21
#  Used to convert strings to hashes
#  MD5, SHA1, SHA256, SHA512
#
#  Email: anivsante2@gmail.com
#
#  Links:
#  	https://github.com/MichaelDim02/BlackJack
#  	https://github.com/MichaelDim02/BlackJack21

def string_input():
	string = raw_input("String: ")
	conversion(string)
def conversion(x):
	md5 = hashlib.md5().hexdigest()
	sha1 = hashlib.sha1().hexdigest()
	sha256 = hashlib.sha256().hexdigest()
	sha512 = hashlib.sha512().hexdigest()
	output(md5, sha1, sha256, sha512)
def output(m, s1, s2, s5):
	print()
	print("MD5:     ",m,"\n")
	print("SHA1:    ",s1,"\n")
	print("SHA256:  ",s2,"\n")
	print("SHA512:  ",s5,"\n")

string_input()
