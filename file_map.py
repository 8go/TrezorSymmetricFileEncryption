import os
import os.path
import sys
import stat
import logging
import struct
import cPickle
import hmac
import hashlib
import base64
import binascii
import mmap
import datetime

from Crypto.Cipher import AES
from Crypto import Random

from encoding import Magic, Padding, PaddingHomegrown

import basics

## File format for encrypted files, version v1
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
	"""Storage of blob read from file and its parameters in memory"""

	MAXPADDEDTREZORENCRYPTSIZE = 1024
	MAXUNPADDEDTREZORENCRYPTSIZE = MAXPADDEDTREZORENCRYPTSIZE - 1

	def __init__(self, trezor, logger):
		assert trezor is not None
		self.blob = {}
		self.trezor = trezor
		self.outerKey = None # outer AES-CBC key, 1st-level encryption
		self.outerIv = None  # IV for data blob encrypted with outerKey
		self.version = None
		self.versionSw = None
		self.noOfEncryptions = None
		self.logger = logger

	def createDecFile(self, fname):
		"""
		read encrypted file, then open, write and save plaintext file
		@param fname: name of the encrypted file to decrypt
		"""
		originalFilename = fname
		head, tail = os.path.split(fname)

		if tail.endswith(basics.TSFEFILEEXT):
			isObfuscated = False
			fname = fname[:-len(basics.TSFEFILEEXT)]
		else:
			isObfuscated = True
			fname = os.path.join(head, self.deobfuscateFilename(tail))

		self.logger.debug("Decryption trying to write to file %s.",fname)

		if os.path.isfile(fname):
			self.logger.warning("File %s exists and decrytion will overwrite it.", fname)
			if not os.access(fname, os.W_OK):
				#os.chmod(fname, stat.S_IRUSR | stat.S_IWUSR )
				self.logger.error("File %s cannot be written. "
					"No write permissions. Skipping it.", fname)
				return

		self.loadBlobFromEncFile(originalFilename)
		with open(fname, 'w+b') as f:
			s = len(self.blob)
			f.write(self.blob)
			if f.tell() != s:
				raise IOError("File IO problem - not enough data written")
			self.logger.debug("Decryption wrote %d bytes to file %s.",s,fname)
			f.flush()
			f.close()
		# overwrite with nonsense to shred memory
		rng = Random.new()
		self.outerKey = rng.read(KEYSIZE)
		return fname # output file name

	def loadBlobFromEncFile(self, fname):
		"""
		Load/read data from encrypted file, decrypt data amd store data in blob
		Requires Trezor connected.

		@param fname: name of the encrypted file to decrypt

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

			self.outerIv = f.read(BLOCKSIZE)
			if len(self.outerIv) != BLOCKSIZE:
				raise IOError("Corrupted disk format - bad IV length")

			self.outerKey = self.unwrapKey(wrappedKey,self.outerIv)

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
			f.close()
			if len(hmacDigest) != MACSIZE:
				raise IOError("Corrupted disk format - HMAC not complete")

			#time-invariant HMAC comparison that also works with python 2.6
			newHmacDigest = hmac.new(self.outerKey, encrypted, hashlib.sha256).digest()
			hmacCompare = 0
			for (ch1, ch2) in zip(hmacDigest, newHmacDigest):
				hmacCompare |= int(ch1 != ch2)
			if hmacCompare != 0:
				raise IOError("Corrupted disk format - HMAC does not match or bad passphrase")

			if self.noOfEncryptions == 2:
				encrypted = self.decryptOnTrezorDevice(encrypted, Magic.levelTwoKey)

			self.blob = self.decryptOuter(encrypted, self.outerIv)

	def createEncFile(self, fname, obfuscate, twice):
		"""
		read plaintext file, then open, write and save encrypted file
		@param fname: name of the plaintext file to encrypt
		@param twice: True if data should be encrypted twice
		"""

		with open(fname, 'rb') as f:
			# Size 0 will read the ENTIRE file into memory!
			m = mmap.mmap(f.fileno(), 0, prot=mmap.PROT_READ) #File is open read-only
			s = m.size()
			self.blob = m.read(s)
			m.close()
			f.close()
		if len(self.blob) != s:
			raise IOError("File IO problem - not enough data read")
		self.logger.debug("Read %d bytes from file %s.",s,fname)
		# encrypt
		rng = Random.new()
		self.outerKey = rng.read(KEYSIZE)
		self.versionSw = basics.TSFEVERSION
		self.noOfEncryptions = 1
		outputfname = self.saveBlobToEncFile(fname, obfuscate, twice)
		# overwrite with nonsense to shred memory
		self.outerKey = rng.read(KEYSIZE)
		return outputfname # output file name

	def saveBlobToEncFile(self, fname, obfuscate, twice):
		"""
		Take blob, encrypt blob, and write encrypted data to disk.
		Requires Trezor connected.

		@param fname: the name of the plaintext file,
			it will be used to derive the name of the encrypted file
		@param obfuscate: bool to indicate if an obfuscated filename (True)
			is desired or a plaintext filename (False) for the encrypted file
		@param twice: True if data should be encrypted twice

		@throws IOError: if writing file failed
		"""
		assert len(self.outerKey) == KEYSIZE
		rnd = Random.new()
		self.outerIv = rnd.read(BLOCKSIZE)
		wrappedKey = self.wrapKey(self.outerKey,self.outerIv)

		if obfuscate:
			head, tail = os.path.split(fname)
			fname = os.path.join(head, self.obfuscateFilename(tail))
		else:
			fname += basics.TSFEFILEEXT

		if os.path.isfile(fname):
			self.logger.warning("File %s exists and encryption will overwrite it.", fname)
			if not os.access(fname, os.W_OK):
				os.chmod(fname, stat.S_IRUSR | stat.S_IWUSR )
				#self.logger.error("File %s cannot be written. "
				#	"No write permissions. Skipping it.", fname)
				#raise IOError("File " + fname + " cannot be written. "
				#	"No write permissions. Skipping it.")

		with file(fname, "wb") as f:
			version = basics.TSFEFILEFORMATVERSION
			futureUse = ""
			f.write(Magic.headerStr)
			f.write(struct.pack("!I", version))
			versionSw = self.versionSw.ljust(16) # add padding
			f.write(versionSw)
			if twice:
				self.noOfEncryptions = 2
			else:
				self.noOfEncryptions = 1
			f.write(struct.pack("!I", self.noOfEncryptions))
			futureUse = futureUse.ljust(32) # add padding
			f.write(futureUse)
			f.write(wrappedKey)
			f.write(self.outerIv)
			encrypted = self.encryptOuter(self.blob, self.outerIv)

			if self.noOfEncryptions == 2:
				encrypted = self.encryptOnTrezorDevice(encrypted, Magic.levelTwoKey)

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
			return fname

	def obfuscateFilename(self, plaintextFileName):
		"""
		Plaintext filename -> pad16 -> AES encrypt on Trezor --> base64 encode
			--> homegrown padding == obfuscated filename
		"""
		pad16 = Padding(BLOCKSIZE).pad(plaintextFileName)
		self.logger.debug("Press confirm on Trezor device to encrypt file "
			"name %s (if necessary).", plaintextFileName)
		# we do not use an IV here so that we can quickly deobfuscate
		# filenames without having to read the file
		encFn = self.trezor.encrypt_keyvalue(Magic.fileNameNode,
			Magic.fileNameKey, pad16, ask_on_encrypt=False, ask_on_decrypt=True)
		bs64 = base64.urlsafe_b64encode(encFn) # mod 4
		ret = PaddingHomegrown().pad(bs64) # mod 16
		self.logger.debug("The obfuscated filename for \"%s\" is \"%s\".",
			plaintextFileName, ret)
		# self.logger.debug("\n\tplaintext is %s (%d), \n\tpad16 is %s (%d), "
		#	"\n\tencFn is %s (%d), \n\tbs64 is %s (%d), \n\thgP is %s (%d)",
		#	plaintextFileName, len(plaintextFileName), pad16, len(pad16),
		#	binascii.hexlify(encFn), len(encFn), bs64, len(bs64), ret, len(ret))
		return ret

	def deobfuscateFilename(self, obfuscatedFileName):
		"""
		obfuscated filename --> homegrown unpadding --> base64 decode
			--> AES decrypt on Trezor -->  unpad16 == Plaintext filename
		"""
		hgUp = PaddingHomegrown().unpad(obfuscatedFileName) # mod 4
		bs64 = base64.urlsafe_b64decode(hgUp) # mod anything
		self.logger.debug("Press confirm on Trezor device to decrypt "
			"file name %s (if necessary).", obfuscatedFileName)
		if len(bs64) % BLOCKSIZE != 0:
			raise ValueError("Critical error. File name " + obfuscatedFileName
				+ " could not be deobfuscated. Skipping it.")
		# we do not use an IV here so that we can quickly deobfuscate filenames
		# without reading the file, even for files that do not exist
		decFn = self.trezor.decrypt_keyvalue(Magic.fileNameNode, Magic.fileNameKey,
			bs64, ask_on_encrypt=False, ask_on_decrypt=True)
		ret = Padding(BLOCKSIZE).unpad(decFn)
		self.logger.debug("The plaintext filename for %s is %s.", obfuscatedFileName, ret)
		# self.logger.debug("\n\tobfuscatedFileName is %s (%d), "
		#	"\n\thgUp is %s (%d), \n\tbs64 is %s (%d), \n\tdecFn is %s (%d), "
		#	"\n\tret is %s (%d)", obfuscatedFileName, len(obfuscatedFileName),
		#	hgUp, len(hgUp), binascii.hexlify(bs64), len(bs64),
		#	decFn, len(decFn), ret, len(ret))
		if len(ret) == 0:
			raise ValueError("Decrypting name of " + obfuscatedFileName +
				" failed. Wrong Trezor device?")
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

	def unwrapKey(self, wrappedOuterKey, iv):
		"""
		Decrypt wrapped outer key using Trezor.
		"""
		self.logger.debug("Press confirm on Trezor device to decrypt "
			"key for first level of file decryption (if necessary).")
		ret = self.trezor.decrypt_keyvalue(Magic.levelOneNode, Magic.levelOneKey,
			wrappedOuterKey, ask_on_encrypt=False, ask_on_decrypt=True, iv=iv)
		if len(ret) == 0:
			raise ValueError("Decrypting data failed. Wrong Trezor device?")
		return ret

	def wrapKey(self, keyToWrap, iv):
		"""
		Encrypt/wrap a key. Its size must be multiple of 16.
		"""
		ret = self.trezor.encrypt_keyvalue(Magic.levelOneNode, Magic.levelOneKey,
			keyToWrap, ask_on_encrypt=False, ask_on_decrypt=True, iv=iv)
		return ret

	def encryptOnTrezorDevice(self, blob, keystring):
		"""
		Encrypt data. Does PKCS#5 padding before encryption.
		Store IV as first block.

		@param keystring: key that will be shown to user on Trezor and
			used to encrypt the data. A string in utf-8
		"""
		self.logger.debug('time entering encryptOnTrezorDevice: %s', datetime.datetime.now())
		rnd = Random.new()
		rndBlock = rnd.read(BLOCKSIZE)
		ukeystring = keystring.decode("utf-8")
		# minimum size of unpadded plaintext as input to trezor.encrypt_keyvalue() is 0    ==> padded that is 16 bytes
		# maximum size of unpadded plaintext as input to trezor.encrypt_keyvalue() is 1023 ==> padded that is 1024 bytes
		# plaintext input to trezor.encrypt_keyvalue() must be a multiple of 16
		# trezor.encrypt_keyvalue() throws error on anythin larger than 1024
		# In order to handle blobs larger than 1023 we junk the blobs
		encrypted = ""
		first = True
		splits=[blob[x:x+self.MAXUNPADDEDTREZORENCRYPTSIZE] for x in range(0,len(blob),self.MAXUNPADDEDTREZORENCRYPTSIZE)]
		curr, max = 0, len(splits)
		for junk in splits:
			padded = Padding(BLOCKSIZE).pad(junk)
			try:
				encrypted += self.trezor.encrypt_keyvalue(Magic.levelTwoNode,
					ukeystring, padded, ask_on_encrypt=False, ask_on_decrypt=first, iv=rndBlock)
			except Exception, e:
				self.logger.critical('Trezor failed. (%s)', e)
				raise
			first = False
			curr += 1
			if self.logger.getEffectiveLevel() == logging.DEBUG:
				print >> sys.stderr, "\rencrypting block", curr, "of", max,
		if self.logger.getEffectiveLevel() == logging.DEBUG:
			print >> sys.stderr, "done"
		ret = rndBlock + encrypted
		self.logger.debug("Trezor encryption: plain-size = %d, encrypted-size = %d", len(blob),  len(ret))
		self.logger.debug('time leaving encryptOnTrezorDevice: %s', datetime.datetime.now())
		return ret

	def decryptOnTrezorDevice(self, encryptedblob, keystring):
		"""
		Decrypt a blob. First block is IV. After decryption strips PKCS#5 padding.

		@param keystring: key that will be shown to user on Trezor and
			was used to encrypt the blob. A string in utf-8.
		"""
		if (len(encryptedblob) > 8388608): # 8M+ and -2 option
			self.logger.warning("This will take more than 10 minutes. Be ready to wait! "
				"Decrypting each Megabyte on the Trezor (model 1) takes about 75 seconds, "
				"or 0.8MB/min. This file will take about %d minutes. If you want to "
				"en/decrypt fast the next time around, remove the `-2` or `--twice` "
				"option when you encrypt a file.", len(encryptedblob) / 819200)
		self.logger.debug('time entering decryptOnTrezorDevice: %s', datetime.datetime.now())
		ukeystring = keystring.decode("utf-8")
		iv, encryptedblob = encryptedblob[:BLOCKSIZE], encryptedblob[BLOCKSIZE:]
		# we junk the input, decrypt and reassemble the plaintext
		blob = ""
		first = True
		self.logger.debug("Press confirm on Trezor device for second level "
			"file decryption on Trezor device itself (if necessary).")
		self.logger.debug("Trezor decryption: encrypted-size = %d", len(encryptedblob))
		splits=[encryptedblob[x:x+self.MAXPADDEDTREZORENCRYPTSIZE] for x in range(0,len(encryptedblob),self.MAXPADDEDTREZORENCRYPTSIZE)]
		curr, max = 0, len(splits)
		for junk in splits:
			try:
				plain = self.trezor.decrypt_keyvalue(Magic.levelTwoNode,
					ukeystring, junk, ask_on_encrypt=False, ask_on_decrypt=first, iv=iv)
			except Exception, e:
				self.logger.critical('Trezor failed. (%s)', e)
				raise
			first = False
			blob += Padding(BLOCKSIZE).unpad(plain)
			curr += 1
			if self.logger.getEffectiveLevel() == logging.DEBUG:
				print >> sys.stderr, "\rdecrypting block", curr, "of", max,
		if self.logger.getEffectiveLevel() == logging.DEBUG:
			print >> sys.stderr, "done"
		self.logger.debug("Trezor decryption: encrypted-size = %d, plain-size = %d",
			len(encryptedblob),  len(blob))
		if len(blob) == 0:
			raise ValueError("Decrypting data failed. Wrong Trezor device?")
		self.logger.debug('time leaving decryptOnTrezorDevice: %s', datetime.datetime.now())
		return blob
