from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import sys
import os
import os.path
import random
import struct
import unicodedata

"""
This is generic code that should work untouched accross all applications.
This code implements generic encoding functions.

Code should work on both Python 2.7 as well as 3.4.
Requires PyQt5.
(Old version supported PyQt4.)
"""


def unpack(fmt, s):
	# 	u = lambda fmt, s: struct.unpack(fmt, s)[0]
	return(struct.unpack(fmt, s)[0])


def pack(fmt, s):
	# 	p = lambda fmt, s: struct.pack(fmt, s)[0]
	return(struct.pack(fmt, s))


def normalize_nfc(txt):
	"""
	Utility function to bridge Py2 and Py3 incompatibilities.
	Convert to NFC unicode.
	Takes string-equivalent or bytes-equivalent and
	returns str-equivalent in NFC unicode format.
	Py2: str (aslias bytes), unicode
	Py3: bytes, str (in unicode format)
	"""
	if sys.version_info[0] < 3:
		if isinstance(txt, unicode):
			return unicodedata.normalize('NFC', txt)
		if isinstance(txt, str):
			return unicodedata.normalize('NFC', txt.decode('utf-8'))
	else:
		if isinstance(txt, bytes):
			return unicodedata.normalize('NFC', txt.decode('utf-8'))
		if isinstance(txt, str):
			return unicodedata.normalize('NFC', txt)


def tobytes(txt):
	"""
	Utility function to bridge Py2 and Py3 incompatibilities.
	Convert to bytes.
	Takes string-equivalent or bytes-equivalent and returns bytesequivalent.
	Py2: str (aslias bytes), unicode
	Py3: bytes, str (in unicode format)
	"""
	if sys.version_info[0] < 3:
		if isinstance(txt, unicode):
			return txt.encode('utf-8')
		if isinstance(txt, str):  # == bytes
			return txt
	else:
		if isinstance(txt, bytes):
			return txt
		if isinstance(txt, str):
			return txt.encode('utf-8')


class Padding(object):
	"""
	PKCS#7 Padding for block cipher having 16-byte blocks
	"""

	def __init__(self, blocksize):
		self.blocksize = blocksize

	def pad(self, s):
		"""
		In Python 2 input s is a string, a char list.
		Python 2 returns a string.
		In Python 3 input s is bytes.
		Python 3 returns bytes.
		"""
		BS = self.blocksize
		if sys.version_info[0] > 2:
			return s + (BS - len(s) % BS) * bytes([BS - len(s) % BS])
		else:
			return s + (BS - len(s) % BS) * chr(BS - len(s) % BS)

	def unpad(self, s):
		if sys.version_info[0] > 2:
			return s[0:-s[-1]]
		else:
			return s[0:-ord(s[-1])]


class PaddingHomegrown(object):
	"""
	Pad filenames that are already base64 encoded. Must have length of multiple of 4.
	Base64 always have a length of mod 4, padded with =
	Examples: YQ==, YWI=, YWJj, YWJjZA==, YWJjZGU=, YWJjZGVm, ...
	On homegrown padding we remove the = pad, then we pad to a mod 16 length.
	If length is already mod 16, it will be padded with 16 chars. So in all cases we pad.
	The last letter always represents how many chars have been padded (A=1, ..., P=16).
	The last letter is in the alphabet A..P.
	The padded letters before the last letter are pseudo-random in the a..zA..Z alphabet.
	"""

	def __init__(self):
		self.homegrownblocksize = 16
		self.base64blocksize = 4

	def pad(self, s):
		"""
		Input must be a string in valid base64 format.
		Returns a string.
		"""
		# the randomness can be poor, it does not matter,
		# it is just used for buffer letters in the file name
		urandom_entropy = os.urandom(64)
		random.seed(urandom_entropy)
		# remove the base64 buffer char =
		t = s.replace(u'=', u'')
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
		"""
		Input must be a string in valid base64 format.
		Returns a string.
		"""
		t = s[0:-(ord(s[-1])-ord('A')+1)]
		BS = self.base64blocksize
		return t + "=" * ((BS - len(t) % BS) % BS)
