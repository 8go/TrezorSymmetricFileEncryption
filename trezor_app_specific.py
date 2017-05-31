from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import os
import os.path
import sys
import stat
import logging
import hmac
import hashlib
import base64
import mmap
import datetime

from Crypto.Cipher import AES
from Crypto import Random

from encoding import pack, unpack, Padding, PaddingHomegrown

import basics
import encoding

# File format for encrypted files, version v1
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

	def __init__(self, trezor, settings):
		assert trezor is not None
		self.blob = None
		self.trezor = trezor
		self.outerKey = None  # outer AES-CBC key, 1st-level encryption
		self.outerIv = None   # IV for data blob encrypted with outerKey
		self.innerIv = None   # IV for inner encryption on Trezor device
		self.version = None
		self.versionSw = None
		self.noOfEncryptions = None
		self.settings = settings
		self.logger = settings.logger
		self.baddress = None  # only used for computing addressIv
		self.baddressIv = None  # only used for obfuscating filenames
		self.setAddress()
		self.setAddressIv()

	def setAddress(self):
		"""
		# Get the first address of first BIP44 account
		# This is the main wallet address.
		# k-th account
		# i-th keypair
		# receive address
		# bip32_path = client.expand_path("44'/0'/k'/0/i")
		"""
		# API is: def get_address(self, coin_name, n, show_display=False, multisig=None, script_type=types.SPENDADDRESS):
		bip32_path = self.trezor.expand_path(u"44'/0'/0'/0/888")  # addr 888
		self.baddress = self.trezor.get_address(u'Bitcoin', bip32_path)

	def setAddressIv(self):
		"""
		compute a Trezor specific Iv
		later used in Trezor file name obfuscation
		"""
		# IV : 16 bytes
		# compute IV as 16-byte MD5 hash of main BTC address
		iv = hashlib.md5(self.baddress.encode('utf-8')).digest()
		if len(iv) != 16:
			self.settings.mlogger.log("IV length not 16 bytes. Aborting.",
				logging.CRITICAL, "Internal Error")
			raise RuntimeError(u"IV length is not 16 bytes.")
		self.baddressIv = iv

	def createDecFile(self, fname):
		"""
		read encrypted file, then open, write and save plaintext file
		@param fname: name of the encrypted file to decrypt
		"""
		originalFilename = fname
		head, tail = os.path.split(fname)

		if tail.endswith(basics.FILEEXT):
			isObfuscated = False
			fname = fname[:-len(basics.FILEEXT)]
		else:
			isObfuscated = True
			fname = os.path.join(head, self.deobfuscateFilename(tail))

		self.settings.mlogger.log("Decryption trying to write to file %s." % (fname), logging.DEBUG, "Encryption")

		if os.path.isfile(fname):
			self.settings.mlogger.log("File %s exists and decrytion will overwrite it." % (fname), logging.WARNING, "Encryption")
			if not os.access(fname, os.W_OK):
				# os.chmod(fname, stat.S_IRUSR | stat.S_IWUSR )
				self.settings.mlogger.log("File %s cannot be written. "
					"No write permissions. Skipping it." % (fname), logging.ERROR, "Encryption")
				raise IOError("File IO error: File %s cannot be written. "
					"No write permissions. Skipping it. "
					"Change file permissions and try again." % (fname))

		self.loadBlobFromEncFile(originalFilename)
		with open(fname, "wb") as f:
			s = len(self.blob)
			f.write(self.blob)
			if f.tell() != s:
				self.settings.mlogger.log("File IO problem: not enough data written "
					"(file=%s, target=%d, done=%d)" % (fname, s, f.tell()), logging.ERROR, "Encryption")
				raise IOError("File IO problem - not enough data written "
					"(file=%s, target=%d, done=%d)" % (fname, s, f.tell()))
			self.settings.mlogger.log("Decryption wrote %d bytes to file %s." % (s, fname), logging.DEBUG, "Encryption")
		# each time we encrypt a file it is different, because the outerkey
		# and the outerIv are different. That is by design.
		# In order to perform a safetyCheck we need the outerkey and outerIv
		# to produce an identical encrypted file.
		outerKey = self.outerKey
		innerIv = self.innerIv
		# overwrite with nonsense to shred memory
		rng = Random.new()
		self.outerKey = rng.read(KEYSIZE)
		if self.innerIv is not None:
			self.innerIv = rng.read(BLOCKSIZE)
		if self.noOfEncryptions == 2:
			isTwice = True
		else:
			isTwice = False
		# isObfuscated, isTwice, outerKey, self.outerIv are only used by the
		# safetyCheckDecrypt()
		return (fname, isObfuscated, isTwice, outerKey, self.outerIv, innerIv)

	def loadBlobFromEncFile(self, fname):
		"""
		Load/read data from encrypted file,
		decrypt data amd store data in blob
		Requires Trezor connected.

		@param fname: name of the encrypted file to decrypt

		@throws IOError: if reading file failed
		"""
		with open(fname, "rb") as f:
			header = f.read(len(basics.Magic.headerStr))
			if header != basics.Magic.headerStr:
				raise IOError("Bad header in storage file")

			version = f.read(4)
			if len(version) != 4 or (unpack("!I", version) != 1):
				raise IOError("Unknown version of storage file")
			self.version = unpack("!I", version)

			versionSw = f.read(16)
			if len(versionSw) != 16:
				raise IOError("Corrupted disk format - bad software version length")
			self.versionSw = versionSw.strip()  # remove padding

			noOfEncryptions = f.read(4)
			if len(noOfEncryptions) != 4:
				raise IOError("Corrupted disk format - Unknown number of encryptions")
			self.noOfEncryptions = unpack("!I", noOfEncryptions)
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

			self.outerKey = self.unwrapKey(wrappedKey, self.outerIv)

			ls = f.read(4)  # these are 4 unused bytes to make it future proof for 4G+ files
			if len(ls) != 4:
				raise IOError("Corrupted disk format - bad unused data length")

			ls = f.read(4)
			if len(ls) != 4:
				raise IOError("Corrupted disk format - bad data length")
			ll = unpack("!I", ls)

			encrypted = f.read(ll)
			if len(encrypted) != ll:
				raise IOError("Corrupted disk format - not enough data bytes")

			hmacDigest = f.read(MACSIZE)
			f.close()
			if len(hmacDigest) != MACSIZE:
				raise IOError("Corrupted disk format - HMAC not complete")

			# time-invariant HMAC comparison that also works with python 2.6
			newHmacDigest = hmac.new(self.outerKey, encrypted, hashlib.sha256).digest()
			hmacCompare = 0
			for (ch1, ch2) in zip(hmacDigest, newHmacDigest):
				hmacCompare |= int(ch1 != ch2)
			if hmacCompare != 0:
				raise IOError("Corrupted disk format - HMAC does not match "
					"or bad passphrase. Try again with the correct passphrase.")

			if self.noOfEncryptions == 2:
				encrypted = self.decryptOnTrezorDevice(encrypted, basics.Magic.levelTwoKey)

			self.blob = self.decryptOuter(encrypted, self.outerIv)

	def createEncFile(self, fname, obfuscate, twice, outerKey=None, outerIv=None, innerIv=None):
		"""
		read plaintext file, then open, write and save encrypted file
		@param fname: name of the plaintext file to encrypt
		@param twice: True if data should be encrypted twice
		@param outerKey: usually None,
			if the same file is encrypted twice
			it is different be default, by design, because the outerKey and
			outerIv and innerIv are random.
			If one wants to produce
			an identical encrypted file multiple time (e.g. for a safetyCheckDec())
			then one needs to fix the outerKey and outerIv.
		@param outerIv: see outerKey
		@param innerIv: see outerKey
		"""

		self.settings.mlogger.log("Opening file %s in order to encrypt it." % (fname), logging.DEBUG, "Encryption")
		with open(fname, "rb") as f:
			# Size 0 will read the ENTIRE file into memory!
			# File is open read-only
			# mmap does not implement __exit__ so we cannot use "with mmap... as m:"
			try:
				m = mmap.mmap(f.fileno(), 0, prot=mmap.PROT_READ)
			except ValueError as e:
				self.settings.mlogger.log("Is file '%s' empty? You cannot encrypt "
					"an empty file. (%s)" % (fname, e), logging.DEBUG, "Encryption")
				raise ValueError("Is file '%s' empty? You cannot encrypt "
					"an empty file. (%s)" % (fname, e))
			s = m.size()
			self.blob = m.read(s)
			del m
		if len(self.blob) != s:
			raise IOError("File IO problem - not enough data read")
		self.settings.mlogger.log("Read %d bytes from file %s." % (s, fname), logging.DEBUG, "Encryption")
		# encrypt
		rng = Random.new()
		self.outerKey = rng.read(KEYSIZE)
		if outerKey is not None:
			self.outerKey = outerKey
		self.versionSw = basics.VERSION_STR
		self.noOfEncryptions = 1
		outputfname = self.saveBlobToEncFile(fname, obfuscate, twice, outerKey, outerIv, innerIv)
		# overwrite with nonsense to shred memory
		self.outerKey = rng.read(KEYSIZE)
		return outputfname  # output file name

	def saveBlobToEncFile(self, fname, obfuscate, twice, outerKey=None, outerIv=None, innerIv=None):
		"""
		Take blob, encrypt blob, and write encrypted data to disk.
		Requires Trezor connected.

		@param fname: the name of the plaintext file,
			it will be used to derive the name of the encrypted file
		@param obfuscate: bool to indicate if an obfuscated filename (True)
			is desired or a plaintext filename (False) for the encrypted file
		@param twice: True if data should be encrypted twice
		@param outerKey: usually None,
			if the same file is encrypted twice
			it is different be default, by design, because the outerKey and outerIv are random.
			If one wants to produce
			an identical encrypted file multiple time (e.g. for a safetyCheckDec())
			then one needs to fix the outerKey and outerIv.
		@param outerIv: see outerKey

		@throws IOError: if writing file failed
		"""
		assert len(self.outerKey) == KEYSIZE
		rnd = Random.new()
		self.outerIv = rnd.read(BLOCKSIZE)
		if outerIv is not None:
			self.outerIv = outerIv
		wrappedKey = self.wrapKey(self.outerKey, self.outerIv)

		if obfuscate:
			head, tail = os.path.split(fname)
			fname = os.path.join(head, self.obfuscateFilename(tail))
		else:
			fname += basics.FILEEXT

		if os.path.isfile(fname):
			self.settings.mlogger.log("File %s exists and encryption will overwrite it." % (fname), logging.WARNING, "Encryption")
			if not os.access(fname, os.W_OK):
				os.chmod(fname, stat.S_IRUSR | stat.S_IWUSR)
				# self.settings.mlogger.log("File %s cannot be written. "
				# 	"No write permissions. Skipping it.", fname)
				# raise IOError("File " + fname + " cannot be written. "
				# 	"No write permissions. Skipping it.")

		with open(fname, "wb") as f:
			version = basics.FILEFORMAT_VERSION
			f.write(basics.Magic.headerStr)
			f.write(pack("!I", version))
			versionSw = self.versionSw.ljust(16)  # add padding
			bversionStr = encoding.tobytes(versionSw)
			if len(bversionStr) != 16:
				raise IOError("Version string cannot be made 16 bytes. Aborting. (\"%s\")" % bversionStr)
			f.write(bversionStr)
			if twice:
				self.noOfEncryptions = 2
			else:
				self.noOfEncryptions = 1
			f.write(pack("!I", self.noOfEncryptions))
			futureUse = b'\x00' * 32  # 32 empty bytes
			f.write(futureUse)
			f.write(wrappedKey)
			f.write(self.outerIv)
			encrypted = self.encryptOuter(self.blob, self.outerIv)

			if self.noOfEncryptions == 2:
				encrypted = self.encryptOnTrezorDevice(encrypted, basics.Magic.levelTwoKey, innerIv)

			hmacDigest = hmac.new(self.outerKey, encrypted, hashlib.sha256).digest()
			f.write(b'\x00\x00\x00\x00')  # unused, fill 4 bytes with 0
			ll = pack("!I", len(encrypted))
			f.write(ll)
			f.write(encrypted)
			f.write(hmacDigest)
			ww = f.tell()
			self.settings.mlogger.log("Wrote %d bytes to file %s." % (ww, fname), logging.DEBUG, "Encryption")
			return fname

	def obfuscateFilenameOld(self, plaintextFileName):
		"""
		Plaintext filename -> pad16 -> AES encrypt on Trezor --> base64 encode
			--> homegrown padding == obfuscated filename
		input: string
		output: string
		This old version was used up to and including version 0.5.0
		"""
		namebytes = encoding.tobytes(plaintextFileName)
		pad16 = Padding(BLOCKSIZE).pad(namebytes)
		# self.settings.mlogger.log("Press confirm on Trezor device to encrypt file "
		# 	"name %s (if necessary).", plaintextFileName)
		# we do not use an IV here so that we can quickly deobfuscate
		# filenames without having to read the file
		encFn = self.trezor.encrypt_keyvalue(basics.Magic.fileNameNode,
			basics.Magic.fileNameKey, pad16, ask_on_encrypt=False, ask_on_decrypt=True)
		bs64 = base64.urlsafe_b64encode(encFn)  # mod 4
		bs64Str = encoding.normalize_nfc(bs64)
		ret = PaddingHomegrown().pad(bs64Str)  # mod 16
		self.settings.mlogger.log("The obfuscated filename for \"%s\" is \"%s\"." %
			(plaintextFileName, ret), logging.DEBUG, "Encryption")
		# self.settings.mlogger.log("\n\tplaintext is %s (%d), \n\tpad16 is %s (%d), "
		# 	"\n\tencFn is %s (%d), \n\tbs64 is %s (%d), \n\thgP is %s (%d)",
		# 	plaintextFileName, len(plaintextFileName), pad16, len(pad16),
		# 	binascii.hexlify(encFn), len(encFn), bs64, len(bs64), ret, len(ret))
		return ret

	def obfuscateFilename(self, plaintextFileName):
		"""
		Plaintext filename -> pad16 -> AES encrypt on Trezor --> base64 encode
			--> homegrown padding == obfuscated filename
		input: string
		output: string
		"""
		namebytes = encoding.tobytes(plaintextFileName)
		pad16 = Padding(BLOCKSIZE).pad(namebytes)
		# self.settings.mlogger.log("Press confirm on Trezor device to encrypt file "
		# 	"name %s (if necessary).", plaintextFileName)
		# we do not use an IV here so that we can quickly deobfuscate
		# filenames without having to read the file
		encFn = self.trezor.encrypt_keyvalue(basics.Magic.fileNameNode,
			basics.Magic.fileNameKey, pad16,
			ask_on_encrypt=False, ask_on_decrypt=True, iv=self.baddressIv)
		bs64 = base64.urlsafe_b64encode(encFn)  # mod 4
		bs64Str = encoding.normalize_nfc(bs64)
		ret = PaddingHomegrown().pad(bs64Str)  # mod 16
		self.settings.mlogger.log("The obfuscated filename for \"%s\" is \"%s\"." %
			(plaintextFileName, ret), logging.DEBUG, "Encryption")
		# self.settings.mlogger.log("\n\tplaintext is %s (%d), \n\tpad16 is %s (%d), "
		# 	"\n\tencFn is %s (%d), \n\tbs64 is %s (%d), \n\thgP is %s (%d)",
		# 	plaintextFileName, len(plaintextFileName), pad16, len(pad16),
		# 	binascii.hexlify(encFn), len(encFn), bs64, len(bs64), ret, len(ret))
		return ret

	def deobfuscateFilenameOld(self, obfuscatedFileName):
		"""
		obfuscated filename --> homegrown unpadding --> base64 decode
			--> AES decrypt on Trezor -->  unpad16 == Plaintext filename
		input: string
		output: string
		This old version was used up to and including version 0.5.0
		"""
		hgUp = PaddingHomegrown().unpad(obfuscatedFileName)  # mod 4
		hgUpBytes = encoding.tobytes(hgUp)
		bs64 = base64.urlsafe_b64decode(hgUpBytes)  # mod anything
		self.settings.mlogger.log("Press confirm on Trezor device to decrypt "
			"file name %s (if necessary)." % (obfuscatedFileName), logging.DEBUG, "Encryption")
		if len(bs64) % BLOCKSIZE != 0:
			raise ValueError("Critical error. File name " + obfuscatedFileName
				+ " could not be deobfuscated. Skipping it.")
		# we do not use an IV here so that we can quickly deobfuscate filenames
		# without reading the file, even for files that do not exist
		decFn = self.trezor.decrypt_keyvalue(basics.Magic.fileNameNode, basics.Magic.fileNameKey,
			bs64, ask_on_encrypt=False, ask_on_decrypt=True)
		ret = Padding(BLOCKSIZE).unpad(decFn)
		retStr = encoding.normalize_nfc(ret)
		self.settings.mlogger.log("The plaintext filename for %s is %s." % (obfuscatedFileName, retStr), logging.DEBUG, "Encryption")
		# self.settings.mlogger.log("\n\tobfuscatedFileName is %s (%d), "
		# 	"\n\thgUp is %s (%d), \n\tbs64 is %s (%d), \n\tdecFn is %s (%d), "
		# 	"\n\tret is %s (%d)", obfuscatedFileName, len(obfuscatedFileName),
		# 	hgUp, len(hgUp), binascii.hexlify(bs64), len(bs64),
		# 	decFn, len(decFn), ret, len(ret))
		if len(retStr) == 0:
			raise ValueError("Decrypting name of " + obfuscatedFileName +
				" failed. Wrong Trezor device? Wrong passphrase?")
		return retStr

	def deobfuscateFilename(self, obfuscatedFileName):
		"""
		obfuscated filename --> homegrown unpadding --> base64 decode
			--> AES decrypt on Trezor -->  unpad16 == Plaintext filename
		input: string
		output: string
		"""
		hgUp = PaddingHomegrown().unpad(obfuscatedFileName)  # mod 4
		hgUpBytes = encoding.tobytes(hgUp)
		bs64 = base64.urlsafe_b64decode(hgUpBytes)  # mod anything
		self.settings.mlogger.log("Press confirm on Trezor device to decrypt "
			"file name %s (if necessary)." % (obfuscatedFileName), logging.DEBUG, "Encryption")
		if len(bs64) % BLOCKSIZE != 0:
			raise ValueError("Critical error. File name " + obfuscatedFileName
				+ " could not be deobfuscated. Skipping it.")
		# we do not use an IV here so that we can quickly deobfuscate filenames
		# without reading the file, even for files that do not exist
		decFn = self.trezor.decrypt_keyvalue(basics.Magic.fileNameNode, basics.Magic.fileNameKey,
			bs64, ask_on_encrypt=False, ask_on_decrypt=True, iv=self.baddressIv)
		ret = Padding(BLOCKSIZE).unpad(decFn)
		retStr = encoding.normalize_nfc(ret)
		# self.settings.mlogger.log("\n\tobfuscatedFileName is %s (%d), "
		# 	"\n\thgUp is %s (%d), \n\tbs64 is %s (%d), \n\tdecFn is %s (%d), "
		# 	"\n\tret is %s (%d)", obfuscatedFileName, len(obfuscatedFileName),
		# 	hgUp, len(hgUp), binascii.hexlify(bs64), len(bs64),
		# 	decFn, len(decFn), ret, len(ret))
		if len(retStr) == 0:
			# try the old version, maybe it is an old file
			return(self.deobfuscateFilenameOld(obfuscatedFileName))
		self.settings.mlogger.log("The plaintext filename for %s is %s." % (obfuscatedFileName, retStr), logging.DEBUG, "Encryption")
		return retStr

	def encryptOuter(self, plaintext, iv):
		"""
		Pad and encrypt with self.outerKey
		"""
		return self.encrypt(plaintext, iv, self.outerKey)

	def encrypt(self, plaintext, iv, key):
		"""
		Pad plaintext with PKCS#5 and encrypt it.
		"""
		self.settings.mlogger.log("AES CBC encryption with key of size %d bits." % (len(key)*8), logging.DEBUG, "Encryption")
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
		self.settings.mlogger.log("AES CBC decryption with key of size %d bits." % (len(key)*8), logging.DEBUG, "Encryption")
		cipher = AES.new(key, AES.MODE_CBC, iv)
		plaintext = cipher.decrypt(ciphertext)
		unpadded = Padding(BLOCKSIZE).unpad(plaintext)
		return unpadded

	def unwrapKey(self, wrappedOuterKey, iv):
		"""
		Decrypt wrapped outer key using Trezor.
		"""
		self.settings.mlogger.log("Press confirm on Trezor device to decrypt "
			"key for first level of file decryption (if necessary).", logging.DEBUG, "Encryption")
		ret = self.trezor.decrypt_keyvalue(basics.Magic.levelOneNode, basics.Magic.levelOneKey,
			wrappedOuterKey, ask_on_encrypt=False, ask_on_decrypt=True, iv=iv)
		if len(ret) == 0:
			raise ValueError("Decrypting data failed. Wrong Trezor device?")
		return ret

	def wrapKey(self, keyToWrap, iv):
		"""
		Encrypt/wrap a key. Its size must be multiple of 16.
		"""
		ret = self.trezor.encrypt_keyvalue(basics.Magic.levelOneNode, basics.Magic.levelOneKey,
			keyToWrap, ask_on_encrypt=False, ask_on_decrypt=True, iv=iv)
		return ret

	def encryptOnTrezorDevice(self, blob, keystring, innerIv=None):
		"""
		Encrypt data. Does PKCS#5 padding before encryption.
		Store IV as first block.

		@param keystring: key that will be shown to user on Trezor and
			used to encrypt the data. A string in utf-8

		@returns: bytes
		"""
		self.settings.mlogger.log('Time entering encryptOnTrezorDevice: %s' % (datetime.datetime.now()), logging.DEBUG, "Encryption")
		rnd = Random.new()
		rndBlock = rnd.read(BLOCKSIZE)
		if innerIv is not None:
			rndBlock = innerIv
		ukeystring = encoding.normalize_nfc(keystring)  # keystring.decode("utf-8")
		# minimum size of unpadded plaintext as input to trezor.encrypt_keyvalue() is 0    ==> padded that is 16 bytes
		# maximum size of unpadded plaintext as input to trezor.encrypt_keyvalue() is 1023 ==> padded that is 1024 bytes
		# plaintext input to trezor.encrypt_keyvalue() must be a multiple of 16
		# trezor.encrypt_keyvalue() throws error on anythin larger than 1024
		# In order to handle blobs larger than 1023 we junk the blobs
		encrypted = b''
		first = True
		splits = [blob[x:x+self.MAXUNPADDEDTREZORENCRYPTSIZE] for x in range(0, len(blob), self.MAXUNPADDEDTREZORENCRYPTSIZE)]
		curr, max = 0, len(splits)
		for junk in splits:
			padded = Padding(BLOCKSIZE).pad(junk)
			try:
				encrypted += self.trezor.encrypt_keyvalue(basics.Magic.levelTwoNode,
					ukeystring, padded, ask_on_encrypt=False, ask_on_decrypt=first, iv=rndBlock)
			except Exception as e:
				self.settings.mlogger.log('Trezor failed. (%s)' % (e), logging.CRITICAL, "Encryption")
				raise
			first = False
			curr += 1
			if self.logger.getEffectiveLevel() == logging.DEBUG:
				sys.stderr.write("\rencrypting block %d of %d" % (curr, max),)
		if self.logger.getEffectiveLevel() == logging.DEBUG:
			sys.stderr.write(" --> done\n")
		ret = rndBlock + encrypted
		self.settings.mlogger.log("Trezor encryption: plain-size = %d, encrypted-size = %d" % (len(blob),  len(ret)), logging.DEBUG, "Encryption")
		self.settings.mlogger.log('Time leaving encryptOnTrezorDevice: %s' % (datetime.datetime.now()), logging.DEBUG, "Encryption")
		return ret

	def decryptOnTrezorDevice(self, encryptedblob, keystring):
		"""
		Decrypt a blob. First block is IV. After decryption strips PKCS#5 padding.

		@param keystring: key that will be shown to user on Trezor and
			was used to encrypt the blob. A string in utf-8.
		@returns bytes
		"""
		if (len(encryptedblob) > 8388608):  # 8M+ and -2 option
			self.settings.mlogger.log("This will take more than 10 minutes. Be ready to wait! "
				"Decrypting each Megabyte on the Trezor (model 1) takes about 75 seconds, "
				"or 0.8MB/min. This file will take about %d minutes. If you want to "
				"en/decrypt fast the next time around, remove the `-2` or `--twice` "
				"option when you encrypt a file." % (len(encryptedblob) // 819200), logging.WARNING, "Encryption")
		self.settings.mlogger.log('Time entering decryptOnTrezorDevice: %s' % (datetime.datetime.now()), logging.DEBUG, "Encryption")
		ukeystring = encoding.normalize_nfc(keystring)  # keystring.decode("utf-8")
		iv, encryptedblob = encryptedblob[:BLOCKSIZE], encryptedblob[BLOCKSIZE:]
		# we junk the input, decrypt and reassemble the plaintext
		blob = b''
		first = True
		self.settings.mlogger.log("Press confirm on Trezor device for second level "
			"file decryption on Trezor device itself (if necessary).", logging.DEBUG, "Encryption")
		self.settings.mlogger.log("Trezor decryption: encrypted-size = %d" % (len(encryptedblob)), logging.DEBUG, "Encryption")
		splits = [encryptedblob[x:x+self.MAXPADDEDTREZORENCRYPTSIZE] for x in range(0, len(encryptedblob), self.MAXPADDEDTREZORENCRYPTSIZE)]
		curr, max = 0, len(splits)
		for junk in splits:
			try:
				plain = self.trezor.decrypt_keyvalue(basics.Magic.levelTwoNode,
					ukeystring, junk, ask_on_encrypt=False, ask_on_decrypt=first, iv=iv)
			except Exception as e:
				self.settings.mlogger.log('Trezor failed. (%s)' % (e), logging.CRITICAL, "Encryption")
				raise
			first = False
			blob += Padding(BLOCKSIZE).unpad(plain)
			curr += 1
			if self.logger.getEffectiveLevel() == logging.DEBUG:
				sys.stderr.write("\rdecrypting block %d of %d" % (curr, max),)
		if self.logger.getEffectiveLevel() == logging.DEBUG:
			sys.stderr.write(" --> done\n")
		self.settings.mlogger.log("Trezor decryption: encrypted-size = %d, plain-size = %d" %
			(len(encryptedblob),  len(blob)), logging.DEBUG, "Encryption")
		if len(blob) == 0:
			raise ValueError("Decrypting data failed. Wrong Trezor device?")
		self.settings.mlogger.log('Time leaving decryptOnTrezorDevice: %s' % (datetime.datetime.now()), logging.DEBUG, "Encryption")
		self.innerIv = iv
		return blob
