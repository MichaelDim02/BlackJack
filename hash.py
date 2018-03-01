from __future__ import print_function
import hashlib

#  hash.py
#  Blackjack & Blackjack21
#  Used to convert strings to hashes
#  MD5, SHA1, SHA256, SHA512
#
#  Email: anivsante2@gmail.com
#
#  Links:
#  	https://github.com/MichaelDim02/BlackJack
#  	https://github.com/MichaelDim02/BlackJack21

def converter():
	string = raw_input("String: ")
	print("\nMD5:    ",hashlib.md5(string).hexdigest())
	print("\nSHA1:   ",hashlib.sha1(string).hexdigest())
	print("\nSHA256: ",hashlib.sha256(string).hexdigest())
	print("\nSHA512: ",hashlib.sha512(string).hexdigest())
converter()
