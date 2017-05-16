import struct

from PyQt4 import QtCore

import os
import os.path
import random


def q2s(s):
	"""Convert QString to UTF-8 string object"""
	return str(s.toUtf8())


def s2q(s):
	"""Convert UTF-8 encoded string to QString"""
	return QtCore.QString.fromUtf8(s)


def u(fmt, s):
	# 	u = lambda fmt, s: struct.unpack(fmt, s)[0]
	return(struct.unpack(fmt, s)[0])


def p(fmt, s):
	# 	u = lambda fmt, s: struct.unpack(fmt, s)[0]
	return(struct.pack(fmt, s))


class Magic(object):
	"""
	Few magic constant definitions so that we know which nodes to search
	for keys.
	"""

	headerStr = "TSFE"
	hdr = u("!I", headerStr)

	# first level encryption
	# unlock key for first level AES encryption, key from Trezor, en/decryption on PC
	levelOneNode = [hdr, u("!I", "DEC1")]
	levelOneKey = "Decrypt file for first time?"  # string to derive wrapping key from

	# second level encryption
	# second level AES encryption, de/encryption on trezor device
	levelTwoNode = [hdr, u("!I", "DEC2")]
	levelTwoKey = "Decrypt file for second time?"

	# only used for filename encryption (no confirm button click desired)
	fileNameNode = [hdr, u("!I", "FLNM")]  # filename encryption for filename obfuscation
	fileNameKey = "Decrypt filename only?"


class Padding(object):
	"""
	PKCS#7 Padding for block cipher having 16-byte blocks
	"""

	def __init__(self, blocksize):
		self.blocksize = blocksize

	def pad(self, s):
		BS = self.blocksize
		return s + (BS - len(s) % BS) * chr(BS - len(s) % BS)

	def unpad(self, s):
		return s[0:-ord(s[-1])]


class PaddingHomegrown(object):
	"""
	Pad filenames that are already base64 encoded. Must have length of multiple of 4.
	Base64 always have a length of mod 4, padded with =
	Examples: YQ==, YWI=, YWJj, YWJjZA==, YWJjZGU=, YWJjZGVm, ...
	On howngrown padding we remove the = pad, then we pad to a mod 16.
	If length is already mod 16, it will be padded with 16 chars. So in all cases we pad.
	The last letter always represents how many chars have been padded (A=1, ..., P=16).
	The last letter is out of the alphabet A..P.
	The padded letters before the last letter are pseudo-random in the a..zA..Z alphabet.
	"""

	def __init__(self):
		self.homegrownblocksize = 16
		self.base64blocksize = 4

	def pad(self, s):
		"""
		input must be in valid base64 format
		"""
		# the randomness can be poor, it does not matter,
		# it is just used for buffer letters in the file name
		urandom_entropy = os.urandom(64)
		random.seed(urandom_entropy)
		# remove the base64 buffer char =
		t = s.translate(None, '=')
		initlen = len(t)
		BS = self.homegrownblocksize
		bufLen = BS - len(t) % BS
		r = initlen*ord(t[-1])*ord(t[:1])
		for x in range(0, bufLen-1):
			# Old version:
			# this was not convenient,
			# on various encryptions of the same file, multiple encrypted files
			# with different names would be created, requiring cleanup by
			# the user as the mapping from plaintext filename to obfuscated
			# filename was not deterministic
			# r = random.randint(0, 51) # old version
			# New version
			# deterministic mapping of plaintext filename to obfuscated file name
			r = (((r+17)*15485863) % 52)
			if r < 26:
				c = chr(r+ord('a'))
			else:
				c = chr(r+ord('A')-26)
			t += c
		t += chr(BS - initlen % BS + ord('A') - 1)
		return t

	def unpad(self, s):
		t = s[0:-(ord(s[-1])-ord('A')+1)]
		BS = self.base64blocksize
		return t + "=" * ((BS - len(t) % BS) % BS)
