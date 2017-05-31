from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import sys
import logging
import re
import datetime
import traceback
import os
import os.path
import stat
import base64
import hashlib
import filecmp

from Crypto import Random

from trezorlib.client import CallException, PinException

import basics
import encoding


def shred(filename, passes, settings=None, logger=None):
	"""
	Shred the file named `filename` `passes` times.
	There is no guarantee that the file will actually be shredded.
	The OS or the smart disk might buffer it in a cache and
	data might remain on the physical disk.
	This is a best effort.

	@param filename: the name of the file to shred
	@type filename: C{string}
	@param passes: how often the file should be overwritten
	@type passes: C{int}
	@param settings: holds settings for how to log info/warnings/errors
	@type settings: L{Settings}
	@param logger: holds logger for where to log info/warnings/errors
	@type logger: L{logging.Logger}
	@return: True if successful, otherwise False
	@rtype: C{bool}
	"""
	try:
		if not os.path.isfile(filename):
			raise IOError("Cannot shred, \"%s\" is not a file." % filename)

		ld = os.path.getsize(filename)
		with open(filename, "wb") as fh:
			for _ in range(int(passes)):
				data = b'\x00' * ld
				fh.write(data)
				fh.seek(0,  0)
		with open(filename, "wb") as fh:
			fh.truncate(0)
		urandom_entropy = os.urandom(64)
		randomBytes1 = hashlib.sha256(urandom_entropy).digest()
		urandom_entropy = os.urandom(64)
		randomBytes2 = hashlib.sha256(urandom_entropy).digest()
		randomB64bytes = base64.urlsafe_b64encode(randomBytes1+randomBytes2)
		randomB64str = encoding.normalize_nfc(randomB64bytes)
		randomB64str = randomB64str.replace(u'=', u'-')
		os.rename(filename, randomB64str)
		os.remove(randomB64str)
	except IOError as e:
		if settings is not None:
			settings.mlogger.log("Skipping shredding of file \"%s\" (IO error: %s)" %
				(filename, e), logging.WARN, "IO Error")
		elif logger is not None:
			logger.warning("Skipping shredding of file \"%s\" (IO error: %s)" %
				(filename, e))
		else:
			print("Skipping shredding of file \"%s\" (IO error: %s)" %
				(filename, e))
		return False
	if settings is not None:
		settings.mlogger.log("File \"%s\" has been shredded and deleted." % filename,
			logging.INFO, "File IO")
	elif logger is not None:
		logger.info("Info: File \"%s\" has been shredded and deleted." % filename)
	else:
		print("Info: File \"%s\" has been shredded and deleted." % filename)
	return True


def analyzeFilename(inputFile, settings):
	"""
	Determine from the input filename if we have to Encrypt or decrypt the file.

	Returns "d" or "e" for decrypt or encrypt
	EncryptObfuscate will not be returned by this function,
	for EncryptObfuscate the user must use -o option.
	The default if nothing is specified is the normal plaintext encrypt.

	If it ends in .tsfe then return "d" (only encrypted files should end in .tsfe)
	If it does not end in .tsfe and has a .
		then return "e" (obfuscated filenames cannot contain .)
	If no . in filename && ( length % 16 != 16 || filename contains letters
		like &, @, ^, %, $, etc. || last letter is not in A..Q )
		then return "e"
		(encrypted obfuscated files have filename length mod 16, do not
		contain special chars except - and _, end in A..Q)
	Else return "d" (no ., length is mod 16, no special chars, end in A..P)

	@param inputFile: filename to analyze
	@type inputFile: C{string}
	@param settings: holds settings for how to log info/warnings/errors
	@type settings: L{Settings}
	"""
	settings.mlogger.log("Analyzing filename %s" % inputFile, logging.DEBUG, "Debug")
	head, tail = os.path.split(inputFile)

	if '.' in tail:
		if tail.endswith(basics.FILEEXT):
			return("d")
		else:
			return("e")
	else:
		if ((len(tail) % 16) == 0) and (re.search(r'[^\-_a-zA-Z0-9]', tail) is None) and (re.search(r'[^\A-P]', tail[-1:]) is None):
			return("d")
		else:
			return("e")


def decryptFileNameOnly(inputFile, settings, fileMap):
	"""
	Decrypt a filename.
	If it ends with .tsfe then the filename is plain text
	Otherwise the filename is obfuscated.

	@param inputFile: filename to decrypt
	@type inputFile: C{string}
	@param settings: holds settings for how to log info/warnings/errors
	@type settings: L{Settings}
	"""
	settings.mlogger.log("Decrypting filename %s" % inputFile, logging.DEBUG, "Debug")
	head, tail = os.path.split(inputFile)

	if tail.endswith(basics.FILEEXT) or (not ((len(tail) % 16 == 0) and
			(re.search(r'[^\-_a-zA-Z0-9]', tail) is None) and
			(re.search(r'[^\A-P]', tail[-1:]) is None))):
		isObfuscated = False
		if tail.endswith(basics.FILEEXT):
			plaintextfname = inputFile[:-len(basics.FILEEXT)]
		else:
			plaintextfname = inputFile
	else:
		isObfuscated = True
		plaintextfname = os.path.join(head, fileMap.deobfuscateFilename(tail))

	phead, ptail = os.path.split(plaintextfname)
	if not isObfuscated:
		settings.mlogger.log("Plaintext filename/path: \"%s\"" % plaintextfname,
			logging.DEBUG, "Filename deobfuscation")
		settings.mlogger.log("Filename/path \"%s\" is already in plaintext." % tail,
			logging.INFO, "Filename deobfuscation")
	else:
		settings.mlogger.log("Encrypted filename/path: \"%s\"" % inputFile,
			logging.DEBUG, "Filename deobfuscation")
		settings.mlogger.log("Plaintext filename/path: \"%s\"" % plaintextfname,
			logging.DEBUG, "Filename deobfuscation")
		settings.mlogger.log("Plaintext filename of \"%s\" is \"%s\"." %
			(tail, ptail), logging.NOTSET,
			"Filename deobfuscation")
	return plaintextfname


def decryptFile(inputFile, settings, fileMap):
	"""
	Decrypt a file.
	If it ends with .tsfe then the filename is plain text
	Otherwise the filename is obfuscated.

	@param inputFile: name of file to decrypt
	@type inputFile: C{string}
	@param settings: holds settings for how to log info/warnings/errors
	@type settings: L{Settings}
	"""
	settings.mlogger.log("Decrypting file %s" % inputFile, logging.DEBUG,
		"Debug")
	head, tail = os.path.split(inputFile)

	if not os.path.isfile(inputFile):
		settings.mlogger.log("File \"%s\" does not exist, is not a proper file, "
			"or is a directory. Skipping it." % inputFile, logging.ERROR,
			"File IO Error")
		return
	else:
		if not os.access(inputFile, os.R_OK):
			settings.mlogger.log("File \"%s\" cannot be read. No read permissions. "
				"Skipping it." % inputFile, logging.ERROR, "File IO Error")
			return

	if tail.endswith(basics.FILEEXT):
		isEncrypted = True
	elif ((len(tail) % 16 == 0) and
			(re.search(r'[^\-_a-zA-Z0-9]', tail) is None) and
			(re.search(r'[^\A-P]', tail[-1:]) is None)):
		isEncrypted = True
	else:
		isEncrypted = False

	if not isEncrypted:
		settings.mlogger.log("File/path seems plaintext: \"%s\"" % inputFile,
			logging.DEBUG, "File decryption")
		settings.mlogger.log("File \"%s\" seems to be already in plaintext. "
			"Decrypting a plaintext file will fail. Skipping file." % tail,
			logging.WARNING, "File decryption")
		return None
	else:
		outputfname, isobfuscated, istwice, outerKey, outerIv, innerIv = fileMap.createDecFile(inputFile)
		# for safety make decrypted file rw to user only
		os.chmod(outputfname, stat.S_IRUSR | stat.S_IWUSR)
		ohead, otail = os.path.split(outputfname)
		settings.mlogger.log("Encrypted file/path: \"%s\"" % inputFile,
			logging.DEBUG, "File decryption")
		settings.mlogger.log("Decrypted file/path: \"%s\"" % outputfname,
			logging.DEBUG, "File decryption")
		settings.mlogger.log("File \"%s\" has been decrypted successfully. "
			"Decrypted file \"%s\" was produced." % (tail, otail),
			logging.NOTSET, "File decryption")
		safe = True
		if settings.SArg and settings.DArg:
			safe = safetyCheckDecrypt(inputFile, outputfname, fileMap, isobfuscated, istwice, outerKey, outerIv, innerIv, settings)
		if safe and os.path.isfile(inputFile) and settings.WArg and settings.DArg:
			# encrypted files are usually read-only, make rw before shred
			os.chmod(inputFile, stat.S_IRUSR | stat.S_IWUSR)
			shred(inputFile, 3, settings)
		rng = Random.new()
		# overwrite with nonsense to shred memory
		outerKey = rng.read(len(outerKey))  # file_map.KEYSIZE
		outerIv = rng.read(len(outerIv))
		if innerIv is not None:
			innerIv = rng.read(len(innerIv))
		del outerKey
		del outerIv
		del innerIv
	return outputfname


def encryptFileNameOnly(inputFile, settings, fileMap):
	"""
	Encrypt a filename.
	Show only what the obfuscated filename would be, without encrypting the file

	@param inputFile: filename to encrypt
	@type inputFile: C{string}
	@param settings: holds settings for how to log info/warnings/errors
	@type settings: L{Settings}
	"""
	settings.mlogger.log("Encrypting filename %s" % inputFile, logging.DEBUG,
		"Debug")
	head, tail = os.path.split(inputFile)

	if analyzeFilename(inputFile, settings) == "d":
		settings.mlogger.log("Filename/path seems decrypted: \"%s\"" % inputFile,
			logging.DEBUG, "File decryption")
		settings.mlogger.log("Filename/path \"%s\" looks like an encrypted file. "
			"Why would you encrypt its filename? This looks strange." % tail,
			logging.WARNING, "Filename obfuscation")

	obfFileName = os.path.join(head, fileMap.obfuscateFilename(tail))

	ohead, otail = os.path.split(obfFileName)
	settings.mlogger.log("Plaintext filename/path: \"%s\"" % inputFile,
		logging.DEBUG, "Filename obfuscation")
	settings.mlogger.log("Obfuscated filename/path: \"%s\"" % obfFileName,
		logging.DEBUG, "Filename obfuscation")
	# Do not modify or remove the next line.
	# The test harness, the test shell script requires it.
	settings.mlogger.log("Obfuscated filename/path of \"%s\" is \"%s\"." % (tail, otail),
		logging.NOTSET, "Filename obfuscation")
	return obfFileName


def encryptFile(inputFile, settings, fileMap, obfuscate, twice, outerKey, outerIv, innerIv):
	"""
	Encrypt a file.
	if obfuscate == false then keep the output filename in plain text and add .tsfe

	@param inputFile: name of file to encrypt
	@type inputFile: C{string}
	@param settings: holds settings for how to log info/warnings/errors
	@type settings: L{Settings}
	@param fileMap: object to use to handle file format of encrypted file
	@type fileMap: L{file_map.FileMap}
	@param obfuscate: bool to indicate if an obfuscated filename (True) is
		desired or a plaintext filename (False)
	@type obfuscate: C{bool}
	@param twice: bool to indicate if file should be encrypted twice
	@type twice: C{bool}
	@param outerKey: usually None,
		if the same file is encrypted twice
		it is different be default, by design, because the outerKey and outerIv are random.
		If one wants to produce
		an identical encrypted file multiple time (e.g. for a safetyCheckDec())
		then one needs to fix the outerKey and outerIv.
		If you want to give it a fixed value, pass it to the function,
		otherwise set it to None.
	@param outerIv: see outerKey
	@param outerKey: 32 bytes
	@param outerIv: 16 bytes
	"""
	settings.mlogger.log("Encrypting file %s" % inputFile, logging.DEBUG,
		"Debug")
	head, tail = os.path.split(inputFile)

	if not os.path.isfile(inputFile):
		settings.mlogger.log("File \"%s\" does not exist, is not a proper file, "
			"or is a directory. Skipping it." % inputFile, logging.ERROR,
			"File IO Error")
		return
	else:
		if not os.access(inputFile, os.R_OK):
			settings.mlogger.log("File \"%s\" cannot be read. No read permissions. "
				"Skipping it." % inputFile, logging.ERROR, "File IO Error")
	if (os.path.getsize(inputFile) > 8388608) and twice:  # 8M+ and -2 option
		settings.mlogger.log("This will take more than 10 minutes. Are you sure "
			"you want to wait? En/decrypting each Megabyte on the Trezor "
			"(model 1) takes about 75 seconds, or 0.8MB/min. The file \"%s\" "
			"would take about %d minutes. If you want to en/decrypt fast "
			"remove the `-2` or `--twice` option." %
			(tail, os.path.getsize(inputFile) // 819200),
			logging.WARNING, "Filename obfuscation")  # 800K/min

	if tail.endswith(basics.FILEEXT):
		isEncrypted = True
	elif ((len(tail) % 16 == 0) and
			(re.search(r'[^\-_a-zA-Z0-9]', tail) is None) and
			(re.search(r'[^\A-P]', tail[-1:]) is None)):
		isEncrypted = True
	else:
		isEncrypted = False

	if isEncrypted:
		settings.mlogger.log("File/path seems encrypted: \"%s\"" % inputFile,
			logging.DEBUG, "File encryption")
		settings.mlogger.log("File \"%s\" seems to be encrypted already. "
			"Are you sure you want to (possibly) encrypt it again?" % tail,
			logging.WARNING, "File enncryption")

	outputfname = fileMap.createEncFile(inputFile, obfuscate, twice, outerKey, outerIv, innerIv)
	# for safety make encrypted file read-only
	os.chmod(outputfname, stat.S_IRUSR)
	ohead, otail = os.path.split(outputfname)
	settings.mlogger.log("Plaintext file/path: \"%s\"" % inputFile,
		logging.DEBUG, "File encryption")
	settings.mlogger.log("Encrypted file/path: \"%s\"" % outputfname,
		logging.DEBUG, "File encryption")
	if twice:
		twicetext = " twice"
	else:
		twicetext = ""
	settings.mlogger.log("File \"%s\" has been encrypted successfully%s. Encrypted "
		"file \"%s\" was produced." % (tail, twicetext, otail), logging.NOTSET,
		"File encryption")
	safe = True
	if settings.SArg and settings.EArg:
		safe = safetyCheckEncrypt(inputFile, outputfname, fileMap, settings)
	if safe and settings.WArg and settings.EArg:
		shred(inputFile, 3, settings)
	return outputfname


def safetyCheckEncrypt(plaintextFname, encryptedFname, fileMap, settings):
	"""
	check if previous encryption worked by
	renaming plaintextFname file to plaintextFname.<random number>.org
	decrypting file named encryptedFname producing new file decryptedFname
	comparing/diffing decryptedFname to original file now named plaintextFname.<random number>.org
	removing decrypted file decryptedFname
	renaming original file plaintextFname.<random number>.org back to input plaintextFname

	@param plaintextFname: name of existing plaintext file whose previous encryption needs to be double-checked
	@type plaintextFname: C{string}
	@param encryptedFname: name of existing encrypted file (i.e. the plaintext file encrypted)
	@type encryptedFname: C{string}
	@param settings: holds settings for how to log info/warnings/errors
	@type settings: L{Settings}
	@param fileMap: object to use to handle file format of encrypted file
	@type fileMap: L{file_map.FileMap}
	@returns: True if safety check passes successfuly, False otherwise
	@rtype: C{bool}
	"""
	urandom_entropy = os.urandom(64)
	randomBytes = hashlib.sha256(urandom_entropy).digest()
	# randomBytes is bytes in Py3, str in Py2
	# base85 encoding not yet implemented in Python 2.7, (requires Python 3+)
	# so we use base64 encoding
	# replace the base64 buffer char =
	randomB64bytes = base64.urlsafe_b64encode(randomBytes)
	# randomB64bytes is bytes in Py3, str in Py2
	randomB64str = encoding.normalize_nfc(randomB64bytes)
	randomB64str = randomB64str.replace(u'=', u'-')
	originalFname = plaintextFname + u"." + randomB64str + u".orignal"
	os.rename(plaintextFname, originalFname)
	decryptedFname = decryptFile(encryptedFname, settings, fileMap)
	aresame = filecmp.cmp(decryptedFname, originalFname, shallow=False)
	ihead, itail = os.path.split(plaintextFname)
	ohead, otail = os.path.split(encryptedFname)
	if aresame:
		settings.mlogger.log("Safety check of file \"%s\" (\"%s\") was successful." %
			(otail, itail),
			logging.INFO, "File encryption")
	else:
		settings.mlogger.log("Fatal error: Safety check of file \"%s\" (\"%s\") failed! "
			"You must inestigate. Encryption was flawed!" %
			(otail, itail),
			logging.CRITICAL, "File encryption")
	os.remove(decryptedFname)
	os.rename(originalFname, plaintextFname)
	return aresame


def safetyCheckDecrypt(encryptedFname, plaintextFname, fileMap, isobfuscated,
	istwice, outerKey, outerIv, innerIv, settings):
	"""
	check if previous decryption worked by
	renaming encryptedFname file to encryptedFname.<random number>.org
	encrypting file named plaintextFname producing new file newencryptedFname
	comparing/diffing newencryptedFname to original file now named encryptedFname.<random number>.org
	removing decrypted file newencryptedFname
	renaming original file encryptedFname.<random number>.org back to input encryptedFname

	@param encryptedFname: name of existing encrypted file whose previous decryption needs to be double-checked
	@type encryptedFname: C{string}
	@param plaintextFname: name of existing plaintext file (i.e. the encrypted file decrypted)
	@type plaintextFname: C{string}
	@param fileMap: object to use to handle file format of encrypted file
	@type fileMap: L{file_map.FileMap}
	@param obfuscate: bool to indicate if encryptedFname was obfuscated  (True) or not  (False) before
	@type obfuscate: C{bool}
	@param twice: bool to indicate if encryptedFname was encrypted twice before
	@type twice: C{bool}
	@param outerKey: usually None,
		if the same file is encrypted twice
		it is different be default, by design, because the outerKey and outerIv are random.
		If one wants to produce
		an identical encrypted file multiple time (e.g. for a safetyCheckDec())
		then one needs to fix the outerKey and outerIv.
		If you want to give it a fixed value, pass it to the function,
		otherwise set it to None.
	@param outerIv: see outerKey
	@param outerKey: 32 bytes
	@param outerIv: 16 bytes
	@param settings: holds settings for how to log info/warnings/errors
	@type settings: L{Settings}
	@returns: True if safety check passes successfuly, False otherwise
	@rtype: C{bool}
	"""
	settings.mlogger.log("Safety check on decrypted file \"%s\" with "
		"obfuscation = %s and double-encryption = %s." %
		(encryptedFname, isobfuscated, istwice),
		logging.DEBUG, "File decryption")
	urandom_entropy = os.urandom(64)
	randomBytes = hashlib.sha256(urandom_entropy).digest()
	# base85 encoding not yet implemented in Python 2.7, (requires Python 3+)
	# so we use base64 encoding
	# replace the base64 buffer char =
	randomB64bytes = base64.urlsafe_b64encode(randomBytes)
	randomB64str = encoding.normalize_nfc(randomB64bytes)
	randomB64str = randomB64str.replace(u'=', u'-')
	originalFname = encryptedFname + u"." + randomB64str + u".orignal"
	os.rename(encryptedFname, originalFname)
	newencryptedFname = encryptFile(plaintextFname, settings, fileMap,
		isobfuscated, istwice, outerKey, outerIv, innerIv)
	aresame = filecmp.cmp(newencryptedFname, originalFname, shallow=False)
	ihead, itail = os.path.split(encryptedFname)
	ohead, otail = os.path.split(plaintextFname)
	if aresame:
		settings.mlogger.log("Safety check of file \"%s\" (\"%s\") was successful." %
			(otail, itail),
			logging.INFO, "File decryption")
	else:
		settings.mlogger.log("Fatal error: Safety check of file \"%s\" (\"%s\") failed! "
			"You must inestigate. Decryption was flawed!" %
			(otail, itail),
			logging.CRITICAL, "File decryption")
	os.remove(newencryptedFname)
	os.rename(originalFname, encryptedFname)
	return aresame


def convertFile(inputFile, fileMap, settings):
	"""
	Encrypt or decrypt one file.
	Which operation will be performed is derived from `settings`
	or from analyzing the filename `inputFile`

	@param inputFile: name of the file to be either encrypted or decrypted
	@type inputFile: C{string}
	@param settings: holds settings for how to log info/warnings/errors
	@type settings: L{Settings}
	@param fileMap: object to use to handle file format of encrypted file
	@type fileMap: L{file_map.FileMap}
	"""
	if settings.DArg:
		# decrypt by choice
		decryptFile(inputFile, settings, fileMap)
	elif settings.MArg:
		# encrypt (name only) by choice
		encryptFileNameOnly(inputFile, settings, fileMap)
	elif settings.NArg:
		# decrypt (name only) by choice
		decryptFileNameOnly(inputFile, settings, fileMap)
	elif settings.EArg and settings.OArg:
		# encrypt and obfuscate by choice
		encryptFile(inputFile, settings, fileMap, True, settings.XArg, None, None, None)
	elif settings.EArg and not settings.OArg:
		# encrypt by choice
		encryptFile(inputFile, settings, fileMap, False, settings.XArg, None, None, None)
	else:
		hint = analyzeFilename(inputFile, settings)
		if hint == "d":
			# decrypt by default
			settings.DArg = True
			decryptFile(inputFile, settings, fileMap)
			settings.DArg = False
		else:
			# encrypt by default
			settings.EArg = True
			encryptFile(inputFile, settings, fileMap, False, settings.XArg, None, None, None)
			settings.EArg = False


def doWork(fileMap, settings, dialog=None):
	"""
	Do the real work, perform the main business logic.
	Input comes from settings.
	Loop through the list of filenames in `settings`
	and process each one.
	This function should be shared by GUI mode and Terminal mode.

	@param fileMap: object to use to handle file format of encrypted file
	@type fileMap: L{file_map.FileMap}
	@param settings: holds settings for how to log info/warnings/errors,
		also holds the mlogger
	@type settings: L{Settings}
	@param dialog: holds GUI window for where to log info/warnings/errors
	@type dialog: L{dialogs.Dialog}
	"""

	settings.mlogger.log("Time entering doWork(): %s" % datetime.datetime.now(),
		logging.DEBUG, "Debug")

	for inputFile in settings.inputFiles:
		try:
			settings.mlogger.log("Working on file: %s" % inputFile,
				logging.DEBUG, "Debug")
			convertFile(inputFile, fileMap, settings)
		except PinException:
			settings.mlogger.log("Trezor reports invalid PIN. Aborting.",
				logging.CRITICAL, "Trezor IO")
			sys.exit(8)
		except CallException:
			# button cancel on Trezor, so exit
			settings.mlogger.log("Trezor reports that user clicked 'Cancel' "
				"on Trezor device. Aborting.", logging.CRITICAL, "Trezor IO")
			sys.exit(6)
		except IOError as e:
			settings.mlogger.log("IO error: %s" % e, logging.CRITICAL,
				"Critical Exception")
			if settings.logger.getEffectiveLevel() == logging.DEBUG:
				traceback.print_exc()  # prints to stderr
		except Exception as e:
			settings.mlogger.log("Critical error: %s" % e, logging.CRITICAL,
				"Critical Exception")
			if settings.logger.getEffectiveLevel() == logging.DEBUG:
				traceback.print_exc()  # prints to stderr
	settings.mlogger.log("Time leaving doWork(): %s" % datetime.datetime.now(),
		logging.DEBUG, "Debug")


def processAll(fileMap, settings, dialog=None):
	"""
	Do the real work, perform the main business logic.
	Input comes from settings (Terminal mode) or dialog (GUI mode).
	Output goes to settings (Terminal mode) or dialog (GUI mode).
	This function should be shared by GUI mode and Terminal mode.

	If dialog is None then processAll() has been called
	from Terminal and there is no GUI.
	If dialog is not None processAll() has been called
	from GUI and there is a window.

	Input is in settings.input,

	@param fileMap: object to use to handle file format of encrypted file
	@type fileMap: L{file_map.FileMap}
	@param settings: holds settings for how to log info/warnings/errors
		used to hold inputs and outputs
	@type settings: L{Settings}
	@param dialog: holds GUI window for access to GUI input, output
	@type dialog: L{dialogs.Dialog}
	"""
	if dialog is not None:
		settings.mlogger.log("Apply button was clicked",
			logging.DEBUG, "Debug")
		settings.gui2Settings(dialog)  # move input from GUI to settings
	doWork(fileMap, settings, dialog)
	if dialog is not None:
		settings.settings2Gui(dialog)  # move output from settings to GUI
		settings.mlogger.log("Apply button was processed, returning to GUI",
			logging.DEBUG, "Debug")
