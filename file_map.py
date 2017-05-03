import os
import sys
import logging
import struct
import cPickle
import hmac
import hashlib
import base64
import binascii

from Crypto.Cipher import AES
from Crypto import Random

from encoding import Magic, Padding, PaddingHomegrown

import basics

## On-disk format
#  4 bytes	header "TSFE"
#  4 bytes	data storage version, version of the .tsfe file format, network order uint32_t
# 16 bytes	software version, version of the encryption program, string
#  4 bytes	1 or 2, how often it was encrypted, network order uint32_t
# 32 bytes	unused, for future use
# 32 bytes	AES-CBC-encrypted wrappedOuterKey (first encryption)
# 16 bytes	IV
#  4 bytes  unused, if one ever wants to go beyond 4G files these 4 bytes will be needed.
#  4 bytes	size of data following (N)
#  N bytes	AES-CBC encrypted blob (this blob is encrypted once [outer] or twice [inner as well])
# 32 bytes	HMAC-SHA256 over data with same key as AES-CBC data struct above (of the N bytes)

BLOCKSIZE = 16
MACSIZE = 32
KEYSIZE = 32

class FileMap(object):
	"""Storage of file blob in memory"""

	MAXPADDEDTREZORENCRYPTSIZE = 1024
	MAXUNPADDEDTREZORENCRYPTSIZE = MAXPADDEDTREZORENCRYPTSIZE - 1

	def __init__(self, trezor, logger):
		assert trezor is not None
		self.blob = {}
		self.trezor = trezor
		self.outerKey = None # outer AES-CBC key
		self.outerIv = None  # IV for data blob encrypted with outerKey
		self.version = None
		self.versionSw = None
		self.noOfEncryptions = None
		self.logger = logger

	def load(self, fname):
		"""
		Load data from disk file, decrypt outer
		layer containing key names. Requires Trezor connected.

		@param fname: filename from where to read the blob

		@throws IOError: if reading file failed
		"""
		with file(fname) as f:
			header = f.read(len(Magic.headerStr))
			if header != Magic.headerStr:
				raise IOError("Bad header in storage file")

			version = f.read(4)
			if len(version) != 4 or ( struct.unpack("!I", version)[0] != 1 ):
				raise IOError("Unknown version of storage file")
			self.version = struct.unpack("!I", version)[0]

			versionSw = f.read(16)
			if len(versionSw) != 16:
				raise IOError("Corrupted disk format - bad software version length")
			self.versionSw = versionSw.strip() # remove padding

			noOfEncryptions = f.read(4)
			if len(noOfEncryptions) != 4:
				raise IOError("Corrupted disk format - Unknown number of encryptions")
			self.noOfEncryptions = struct.unpack("!I", noOfEncryptions)[0]
			if self.noOfEncryptions < 1 or self.noOfEncryptions > 2:
				raise IOError("Unknown number of encryptions found in file")

			futureUse = f.read(32)
			if len(futureUse) != 32:
				raise IOError("Corrupted disk format - bad future-use field length")

			wrappedKey = f.read(KEYSIZE)
			if len(wrappedKey) != KEYSIZE:
				raise IOError("Corrupted disk format - bad wrapped key length")

			self.outerKey = self.unwrapKey(wrappedKey)

			self.outerIv = f.read(BLOCKSIZE)
			if len(self.outerIv) != BLOCKSIZE:
				raise IOError("Corrupted disk format - bad IV length")

			ls = f.read(4) # these are 4 unused bytes to make it future proof for 4G+ files
			if len(ls) != 4:
				raise IOError("Corrupted disk format - bad unused data length")

			ls = f.read(4)
			if len(ls) != 4:
				raise IOError("Corrupted disk format - bad data length")
			l = struct.unpack("!I", ls)[0]

			encrypted = f.read(l)
			if len(encrypted) != l:
				raise IOError("Corrupted disk format - not enough data bytes")

			hmacDigest = f.read(MACSIZE)
			if len(hmacDigest) != MACSIZE:
				raise IOError("Corrupted disk format - HMAC not complete")

			#time-invariant HMAC comparison that also works with python 2.6
			newHmacDigest = hmac.new(self.outerKey, encrypted, hashlib.sha256).digest()
			hmacCompare = 0
			for (ch1, ch2) in zip(hmacDigest, newHmacDigest):
				hmacCompare |= int(ch1 != ch2)
			if hmacCompare != 0:
				raise IOError("Corrupted disk format - HMAC does not match or bad passphrase")

			serialized = self.decryptOuter(encrypted, self.outerIv)

			if self.noOfEncryptions == 2:
				# ZZZ
				serialized = serialized

			self.blob = serialized
			f.close()

	def save(self, fname, obfuscate):
		"""
		Write data to disk, encrypt it. Requires Trezor connected.

		@param fname: base of the filename where the encrypted blob is written to, it will be adjusted with a new extension or obfuscated.
		@param obfuscate: bool to indicate if an obfuscated filename (True) is desired or a plaintext filename (False)

		@throws IOError: if writing file failed
		"""
		assert len(self.outerKey) == KEYSIZE
		rnd = Random.new()
		self.outerIv = rnd.read(BLOCKSIZE)
		wrappedKey = self.wrapKey(self.outerKey)

		if obfuscate:
			head, tail = os.path.split(fname)
			fname = os.path.join(head, self.obfuscateFilename(tail))  # ZZZ
		else:
			fname += basics.TSFEFILEEXT

		if os.path.isfile(fname):
			self.logger.warning("File %s exists and decrytion will overwrite it.", fname)
			if not os.access(fname, os.W_OK):
				self.logger.error("File %s cannot be written. No write permissions. Skipping it.", fname)
				raise ValueError("File " + fname + " cannot be written. No write permissions. Skipping it.")

		with file(fname, "wb") as f:
			version = basics.TSFEFILEFORMATVERSION
			futureUse = ""
			f.write(Magic.headerStr)
			f.write(struct.pack("!I", version))
			versionSw = self.versionSw.ljust(16) # add padding
			f.write(versionSw)
			f.write(struct.pack("!I", self.noOfEncryptions))
			futureUse = futureUse.ljust(32) # add padding
			f.write(futureUse)
			f.write(wrappedKey)
			f.write(self.outerIv)
			serialized = self.blob
			encrypted = self.encryptOuter(serialized, self.outerIv)

			if self.noOfEncryptions == 2:
				# ZZZ
				encrypted = encrypted

			hmacDigest = hmac.new(self.outerKey, encrypted, hashlib.sha256).digest()
			f.write(b'\x00\x00\x00\x00') # unused, fill 4 bytes with 0
			l = struct.pack("!I", len(encrypted))
			f.write(l)
			f.write(encrypted)
			f.write(hmacDigest)
			ww = f.tell()
			f.flush()
			f.close()
			self.logger.debug("Wrote %d bytes to file %s.", ww, fname)

	def obfuscateFilename(self, plaintextFileName):
		"""
		Plaintext filename -> pad16 -> AES encrypt on Trezor --> base64 encode --> homegrown padding == obfuscated filename
		"""
		pad16 = Padding(BLOCKSIZE).pad(plaintextFileName)
		self.logger.debug("Press confirm on Trezor device to encrypt file name %s (if necessary).", plaintextFileName)
		encFn = self.trezor.encrypt_keyvalue(Magic.fileNameNode, Magic.fileNameKey, pad16, ask_on_encrypt=False, ask_on_decrypt=True)
		bs64 = base64.urlsafe_b64encode(encFn) # mod 4
		ret = PaddingHomegrown().pad(bs64) # mod 16
		self.logger.debug("The obfuscated filename for %s is %s.", plaintextFileName, ret)
		self.logger.debug("\nplaintext is %s (%d), \npad16 is %s (%d), \nencFn is %s (%d), \nbs64 is %s (%d), \nhgP is %s (%d)", plaintextFileName, len(plaintextFileName), pad16, len(pad16), binascii.hexlify(encFn), len(encFn), bs64, len(bs64), ret, len(ret))
		return ret

	def deobfuscateFilename(self, obfuscatedFileName):
		"""
		obfuscated filename --> homegrown unpadding --> base64 decode --> AES decrypt on Trezor -->  unpad16 == Plaintext filename
		"""
		hgUp = PaddingHomegrown().unpad(obfuscatedFileName) # mod 4
		bs64 = base64.urlsafe_b64decode(hgUp) # mod anything
		self.logger.debug("Press confirm on Trezor device to decrypt file name %s (if necessary).", obfuscatedFileName)
		if len(bs64) % BLOCKSIZE != 0:
			raise ValueError("Internal error. File name " + obfuscatedFileName + " could not be deobfuscated. Skipping it.")
		decFn = self.trezor.decrypt_keyvalue(Magic.fileNameNode, Magic.fileNameKey, bs64, ask_on_encrypt=False, ask_on_decrypt=True)
		ret = Padding(BLOCKSIZE).unpad(decFn)
		self.logger.debug("The plaintext filename for %s is %s.", obfuscatedFileName, ret)
		self.logger.debug("\nobfuscatedFileName is %s (%d), \nhgUp is %s (%d), \nbs64 is %s (%d), \ndecFn is %s (%d), \nret is %s (%d)", obfuscatedFileName, len(obfuscatedFileName), hgUp, len(hgUp), binascii.hexlify(bs64), len(bs64), decFn, len(decFn), ret, len(ret))
		if len(ret) == 0:
			raise ValueError("Decrypting name of " + obfuscatedFileName + " failed. Wrong Trezor device?")
		return ret

	def encryptOuter(self, plaintext, iv):
		"""
		Pad and encrypt with self.outerKey
		"""
		return self.encrypt(plaintext, iv, self.outerKey)

	def encrypt(self, plaintext, iv, key):
		"""
		Pad plaintext with PKCS#5 and encrypt it.
		"""
		cipher = AES.new(key, AES.MODE_CBC, iv)
		padded = Padding(BLOCKSIZE).pad(plaintext)
		return cipher.encrypt(padded)

	def decryptOuter(self, ciphertext, iv):
		"""
		Decrypt with self.outerKey and unpad
		"""
		return self.decrypt(ciphertext, iv, self.outerKey)

	def decrypt(self, ciphertext, iv, key):
		"""
		Decrypt ciphertext, unpad it and return
		"""
		cipher = AES.new(key, AES.MODE_CBC, iv)
		plaintext = cipher.decrypt(ciphertext)
		unpadded = Padding(BLOCKSIZE).unpad(plaintext)
		return unpadded

	def unwrapKey(self, wrappedOuterKey):
		"""
		Decrypt wrapped outer key using Trezor.
		"""
		self.logger.debug("Press confirm on Trezor device to decrypt key for first level of file decryption (if necessary).")
		ret = self.trezor.decrypt_keyvalue(Magic.unlockNode, Magic.unlockKey, wrappedOuterKey, ask_on_encrypt=False, ask_on_decrypt=True)
		if len(ret) == 0:
			raise ValueError("Decrypting data failed. Wrong Trezor device?")
		return ret

	def wrapKey(self, keyToWrap):
		"""
		Encrypt/wrap a key. Its size must be multiple of 16.
		"""
		ret = self.trezor.encrypt_keyvalue(Magic.unlockNode, Magic.unlockKey, keyToWrap, ask_on_encrypt=False, ask_on_decrypt=True)
		return ret

	def encryptPassword(self, password, groupName):
		"""
		Encrypt a password. Does PKCS#5 padding before encryption.
		Store IV as first block.

		@param groupName key that will be shown to user on Trezor and
			used to encrypt the password. A string in utf-8
		"""
		rnd = Random.new()
		rndBlock = rnd.read(BLOCKSIZE)
		ugroup = groupName.decode("utf-8")
		# minimum size of unpadded plaintext as input to trezor.encrypt_keyvalue() is 0    ==> padded that is 16 bytes
		# maximum size of unpadded plaintext as input to trezor.encrypt_keyvalue() is 1023 ==> padded that is 1024 bytes
		# plaintext input to trezor.encrypt_keyvalue() must be a multiple of 16
		# trezor.encrypt_keyvalue() throws error on anythin larger than 1024
		# In order to handle passwords+comments larger than 1023 we junk the passwords+comments
		encrypted = ""
		first = True
		splits=[password[x:x+self.MAXUNPADDEDTREZORENCRYPTSIZE] for x in range(0,len(password),self.MAXUNPADDEDTREZORENCRYPTSIZE)]
		for junk in splits:
			padded = Padding(BLOCKSIZE).pad(junk)
			encrypted += self.trezor.encrypt_keyvalue(Magic.groupNode, ugroup, padded, ask_on_encrypt=False, ask_on_decrypt=first, iv=rndBlock)
			first = False
		ret = rndBlock + encrypted
		self.logger.debug("Trezor encryption: plain-size = %d, encrypted-size = %d", len(password),  len(encrypted))
		return ret

	def decryptPassword(self, encryptedPassword, groupName):
		"""
		Decrypt a password. First block is IV. After decryption strips PKCS#5 padding.

		@param groupName key that will be shown to user on Trezor and
			was used to encrypt the password. A string in utf-8.
		"""
		ugroup = groupName.decode("utf-8")
		iv, encryptedPassword = encryptedPassword[:BLOCKSIZE], encryptedPassword[BLOCKSIZE:]
		# we junk the input, decrypt and reassemble the plaintext
		password = ""
		first = True
		self.logger.debug("Press confirm on Trezor device for second level file decryption (if necessary).")
		splits=[encryptedPassword[x:x+self.MAXPADDEDTREZORENCRYPTSIZE] for x in range(0,len(encryptedPassword),self.MAXPADDEDTREZORENCRYPTSIZE)]
		for junk in splits:
			plain = self.trezor.decrypt_keyvalue(Magic.groupNode, ugroup, junk, ask_on_encrypt=False, ask_on_decrypt=first, iv=iv)
			first = False
			password += Padding(BLOCKSIZE).unpad(plain)
		if len(password) == 0:
			raise ValueError("Decrypting data failed. Wrong Trezor device?")
		return password
