import sys
import struct
import logging
import getopt
import re
import datetime
import traceback
import os
import os.path
import stat
import base64
import hashlib
import filecmp

from PyQt4 import QtCore
from PyQt4 import QtGui

from trezorlib.client import CallException, PinException

from encoding import q2s, s2q
import basics

class Settings(object):
	"""
	Settings, command line options, GUI selected values
	"""

	def __init__(self, logger):
		self.logger = logger
		self.VArg = False
		self.HArg = False
		self.TArg = False
		self.EArg = False
		self.OArg = False
		self.DArg = False
		self.MArg = False
		self.NArg = False
		self.XArg = False # -2, --twice
		self.PArg = None
		self.SArg = False # Safety check
		self.WArg = False # Wipe plaintxt after encryption
		self.inputFiles = [] # list of input filenames

	def printSettings(self):
		self.logger.debug("self.VArg = %s", self.VArg)
		self.logger.debug("self.HArg = %s", self.HArg)
		self.logger.debug("self.TArg = %s", self.TArg)
		self.logger.debug("self.EArg = %s", self.EArg)
		self.logger.debug("self.OArg = %s", self.OArg)
		self.logger.debug("self.DArg = %s", self.DArg)
		self.logger.debug("self.MArg = %s", self.MArg)
		self.logger.debug("self.NArg = %s", self.NArg)
		self.logger.debug("self.XArg = %s", self.XArg)
		self.logger.debug("self.PArg = %s", self.PArg)
		self.logger.debug("self.SArg = %s", self.SArg)
		self.logger.debug("self.WArg = %s", self.WArg)
		self.logger.debug("self.inputFiles = %s", str(self.inputFiles))

	def gui2Settings(self, dialog, trezor):
		trezor.prefillPassphrase(q2s(dialog.pw1()))
		self.DArg = dialog.dec()
		self.NArg = dialog.decFn()
		self.EArg = dialog.enc()
		self.MArg = dialog.encFn()
		self.OArg = dialog.encObf()
		self.XArg = dialog.encTwice()
		self.SArg = dialog.encSafe()
		self.WArg = dialog.encWipe() or dialog.decWipe()
		self.PArg = q2s(dialog.pw1())
		if self.PArg is None:
			self.PArg = ""
		self.inputFiles = dialog.selectedFiles()
		self.printSettings()

	def settings2Gui(self, dialog, trezor):
		dialog.setVersion(basics.TSFEVERSION)
		dialog.setDescription("")
		dialog.setSelectedFile(self.inputFiles)
		dialog.setSelectedFiles(self.inputFiles)
		dialog.setDec(self.DArg)
		dialog.setDecFn(self.NArg)
		dialog.setDecWipe(self.WArg and self.DArg)
		dialog.setEnc(self.EArg)
		dialog.setEncFn(self.MArg)
		dialog.setEncObf(self.OArg and self.EArg)
		dialog.setEncTwice(self.XArg and self.EArg)
		dialog.setEncSafe(self.SArg and self.EArg)
		dialog.setEncWipe(self.WArg and self.EArg)
		dialog.setPw1(self.PArg)
		dialog.setPw2(self.PArg)
		self.printSettings()


def shred(filename, passes, settings = None, logger = None, dialog = None):
	"""
	There is no guarantee that the file will actually be shredded.
	The OS or the smart disk might buffer it in a cache and
	data might remain on the physical disk.
	This is a best effort.
	"""
	try:
		if not os.path.isfile(filename):
			raise IOError("Cannot shred, \"%s\" is not a file." % filename)

		ld = os.path.getsize(filename)
		fh = open(filename,  "w")
		for _ in range(int(passes)):
			data = "0" * ld
			fh.write(data)
			fh.seek(0,  0)
		fh.close()
		fh = open(filename,  "w")
		fh.truncate(0)
		fh.close()
		urandom_entropy = os.urandom(64)
		randomBin = hashlib.sha256(urandom_entropy).digest()
		randomB64 = base64.urlsafe_b64encode(randomBin).replace("=", "-")
		urandom_entropy = os.urandom(64)
		randomBin = hashlib.sha256(urandom_entropy).digest()
		randomB64 = randomB64 + base64.urlsafe_b64encode(randomBin).replace("=", "-")
		os.rename(filename, randomB64)
		os.remove(randomB64)
	except IOError, e:
		if settings is not None and logger is not None and dialog is not None:
			reportLogging("Skipping shredding of file \"%s\" (IO error: %s)" %
				(filename, e), logging.WARN,
				"IO Error", settings, logger, dialog)
		elif logger is not None:
			logger.warning("Skipping shredding of file \"%s\" (IO error: %s)" %
				(filename, e))
		else:
			print("Skipping shredding of file \"%s\" (IO error: %s)" %
				(filename, e))
		return False
	if settings is not None and logger is not None and dialog is not None:
		reportLogging("File \"%s\" has been shredded and deleted." % filename,
			logging.INFO, "File IO", settings, logger, dialog)
	elif logger is not None:
		logger.info("Info: File \"%s\" has been shredded and deleted." % filename)
	else:
		print("Info: File \"%s\" has been shredded and deleted." % filename)
	return True

def usage():
	print """TrezorSymmetricFileEncryption.py [-v] [-h] [-l <level>] [-t] [-2] [-s] [-w] [-o | -e | -d | -m | -n] [-p <passphrase>] <files>
		-v, --verion
				print the version number
		-h, --help
				print short help text
		-l, --logging
				set logging level, integer from 1 to 5, 1=full logging, 5=no logging
		-t, --terminal
				run in the terminal, except for a possible PIN query
				and a Passphrase query this avoids the GUI
		-m, --encnameonly
				just encrypt the plaintext filename, show what the obfuscated
				filename would be; does not encrypt the file itself;
				incompaible with `-d` and `-n`
		-n, --decnameonly
				just decrypt the obfuscated filename;
				does not decrypt the file itself;
				incompaible with `-o`, `-e`, and `-m`
		-d, --decrypt
				decrypt file
		-e, --encrypt
				encrypt file and keep output filename as plaintext
				(appends .tsfe suffix to input file)
		-o, --obfuscatedencrypt
				encrypt file and obfuscate output file name
		-2, --twice
				paranoid mode; encrypt file a second time on the Trezor chip itself;
				only relevant for `-e` and `-o`; ignored in all other cases.
				Consider filesize: The Trezor chip is slow. 1M takes roughly 75 seconds.
		-p, --passphrase
				master passphrase used for Trezor.
				It is recommended that you do not use this command line option
				but rather give the passphrase through a small window interaction.
		-s, --safety
				doublechecks the encryption process by decrypting the just
				encrypted file immediately and comparing it to original file;
				only relevant for `-e` and `-o`; ignored in all other cases.
				Primarily useful for testing.
		-w, --wipe
				shred the inputfile after creating the output file
				i.e. shred the plaintext file after encryption or
				shred the encrypted file after decryption;
				only relevant for `-d`, `-e` and `-o`; ignored in all other cases.
				Use with extreme caution. May be used together with `-s`.
		<files>
				one or multiple files to be encrypted or decrypted

		All arguments are optional.

		All output files are always placed in the same directory as the input files.

		By default the GUI will be used.

		You can avoid the GUI by using `-t`, forcing the Terminal mode.
		If you specify filename, possibly some `-o`, `-e`, or `-d` option, then
		only PIN and Passphrase will be collected through windows.

		Most of the time TrezorSymmetricFileEncryption can detect automatically if
		it needs to decrypt or encrypt by analyzing the given input file name.
		So, in most of the cases you do not need to specify any
		de/encryption option.
		TrezorSymmetricFileEncryption will simply do the right thing.
		In the very rare case that TrezorSymmetricFileEncryption determines
		the wrong encrypt/decrypt operation you can force it to use the right one
		by using either `-e` or `-d` or selecting the appropriate option in the GUI.

		If TrezorSymmetricFileEncryption automatically determines
		that it has to encrypt of file, it will chose by default the
		`-e` option, and create a plaintext encrypted files with an `.tsfe` suffix.

		If you want the output file name to be obfuscated you
		must use the `-o` (obfuscate) flag or select that option in the GUI.

		Be aware of computation time and file sizes when you use `-2` option.
		Encrypting on the Trezor takes time: 1M roughtly 75sec. 50M about 1h.
		Without `-2` it is very fast, a 1G file taking roughly 15 seconds.

		For safety the file permission of encrypted files is set to read-only.

		Examples:
		# specify everything in the GUI
		TrezorSymmetricFileEncryption.py

		# specify everything in the GUI, set logging to verbose Debug level
		TrezorSymmetricFileEncryption.py -l 1

		# encrypt contract producing contract.doc.tsfe
		TrezorSymmetricFileEncryption.py contract.doc

		# encrypt contract and obfuscate output producing e.g. TQFYqK1nha1IfLy_qBxdGwlGRytelGRJ
		TrezorSymmetricFileEncryption.py -o contract.doc

    	# encrypt contract and obfuscate output producing e.g. TQFYqK1nha1IfLy_qBxdGwlGRytelGRJ
    	# performs safety check and then shreds contract.doc
    	TrezorSymmetricFileEncryption.py -e -o -s -w contract.doc

		# decrypt contract producing contract.doc
		TrezorSymmetricFileEncryption.py contract.doc.tsfe

		# decrypt obfuscated contract producing contract.doc
		TrezorSymmetricFileEncryption.py TQFYqK1nha1IfLy_qBxdGwlGRytelGRJ

		# shows plaintext name of encrypted file, e.g. contract.doc
		TrezorSymmetricFileEncryption.py -n TQFYqK1nha1IfLy_qBxdGwlGRytelGRJ

		Keyboard shortcuts of GUI:
		Apply, Save: Control-A, Control-S
		Cancel, Quit: Esc, Control-Q
		Copy to clipboard: Control-C
		Version, About: Control-V
		Set encrypt operation: Control-E
		Set decrypt operation: Control-D
		Set obfuscate option: Control-O
		Set twice option: Control-2
		Set safety option: Control-T
		Set wipe option: Control-W
		"""

def printVersion():
	print "Version: " + basics.TSFEVERSION

def parseArgs(argv, settings, logger):
	try:
		opts, args = getopt.getopt(argv,"vhl:tmn2swdeop:",
			["version","help","logging=","terminal","encnameonly","decnameonly",
			"twice","safety","decrypt","encrypt","obfuscatedencrypt","passphrase="])
	except getopt.GetoptError, e:
		msgBox = QtGui.QMessageBox(QtGui.QMessageBox.Critical, "Wrong arguments", "Error: " + str(e))
		msgBox.exec_()
		logger.critical('Wrong arguments. Error: %s.', str(e))
		sys.exit(2)
	loglevelused = False
	for opt, arg in opts:
		if opt in ("-h","--help"):
			usage()
			sys.exit()
		elif opt in ("-v", "--version"):
			printVersion()
			sys.exit()
		elif opt in ("-l", "--logging"):
			loglevelarg = arg
			loglevelused = True
		elif opt in ("-t", "--terminal"):
			settings.TArg = True
		elif opt in ("-m", "--encnameonly"):
			settings.MArg = True
		elif opt in ("-n", "--decnameonly"):
			settings.NArg = True
		elif opt in ("-d", "--decrypt"):
			settings.DArg = True
		elif opt in ("-e", "--encrypt"):
			settings.EArg = True
		elif opt in ("-o", "--obfuscatedencrypt"):
			settings.OArg = True
		elif opt in ("-2", "--twice"):
			settings.XArg = True
		elif opt in ("-s", "--safety"):
			settings.SArg = True
		elif opt in ("-w", "--wipe"):
			settings.WArg = True
		elif opt in ("-p", "--passphrase"):
			settings.PArg = arg

	if loglevelused:
		try:
			loglevel = int(loglevelarg)
		except Exception, e:
			reportLogging("Logging level not specified correctly. "
				"Must be integer between 1 and 5. (%s)" % loglevelarg, logging.CRITICAL,
				"Wrong arguments", settings, logger)
			sys.exit(18)
		if loglevel > 5 or loglevel < 1:
			reportLogging("Logging level not specified correctly. "
				"Must be integer between 1 and 5. (%s)" % loglevelarg, logging.CRITICAL,
				"Wrong arguments", settings, logger)
			sys.exit(19)
		basics.LOGGINGLEVEL = loglevel * 10 # https://docs.python.org/2/library/logging.html#levels
		logger.setLevel(basics.LOGGINGLEVEL)
		logger.info('Logging level set to %s (%d).',
			logging.getLevelName(basics.LOGGINGLEVEL), basics.LOGGINGLEVEL)

	if (settings.DArg and settings.EArg) or (settings.DArg and settings.OArg):
		reportLogging("You cannot specify both decrypt and encrypt. "
			"It is one or the other. Either -d or -e or -o.", logging.CRITICAL,
			"Wrong arguments", settings, logger)
		sys.exit(2)
	if (settings.MArg and settings.DArg) or (settings.MArg and settings.NArg):
		reportLogging("You cannot specify both \"encrypt filename\" and "
			"\"decrypt file(name)\". It is one or the other. "
			"Don't use -m when using -d or -n (and vice versa).", logging.CRITICAL,
			"Wrong arguments", settings, logger)
		sys.exit(2)
	if (settings.NArg and settings.EArg) or (settings.NArg and settings.OArg) or (settings.NArg and settings.MArg):
		reportLogging("You cannot specify both \"decrypt filename\" and "
			"\"encrypt file(name)\". It is one or the other. Don't use "
			"-n when using -e, -o, or -m (and vice versa).", logging.CRITICAL,
			"Wrong arguments", settings, logger)
		sys.exit(2)
	if settings.DArg or settings.NArg or settings.MArg:
		settings.XArg = False # X is relevant only when -e or -o is set
	if settings.OArg:
		settings.EArg = True # treat O like an extra flag, used in addition
	if settings.MArg:
		settings.EArg = False
		settings.OArg = False
	if settings.NArg:
		settings.DArg = False
	settings.inputFiles = args
	settings.printSettings()

def reportLogging(str, level, title, settings, logger, dialog=None):
	"""
	Displays string str depending on scenario:
	a) in terminal mode: thru logger (except if loglevel == NOTSET)
	b) in GUI mode and GUI window open: (dialog!=None) in Status textarea of GUI window
	c) in GUI mode but window still/already closed: (dialog=None) thru QMessageBox()

	@param str: string to report/log
	@param level: log level from DEBUG to CRITICAL
	@param title: window title text
	"""
	if dialog is None:
		guiExists = False
	else:
		guiExists = True
	if level == logging.NOTSET:
		if settings.TArg:
			print str # stdout
		elif guiExists:
			print str # stdout
			dialog.appendDescription("<br>%s" %	(str))
		else:
			print str # stdout
			msgBox = QtGui.QMessageBox(QtGui.QMessageBox.Information,
				title, "%s" % (str))
			msgBox.exec_()
	elif level == logging.DEBUG:
		if settings.TArg:
			logger.debug(str)
		elif guiExists:
			logger.debug(str)
			if logger.getEffectiveLevel() <= level:
				dialog.appendDescription("<br>Debug: %s" %	(str))
		else:
			# don't spam the user with too many pop-ups
			# For debug, instead of a pop-up we write to stdout
			logger.debug(str)
	elif level == logging.INFO:
		if settings.TArg:
			logger.info(str)
		elif guiExists:
			logger.info(str)
			if logger.getEffectiveLevel() <= level:
				dialog.appendDescription("<br>Info: %s" %	(str))
		else:
			logger.info(str)
			if logger.getEffectiveLevel() <= level:
				msgBox = QtGui.QMessageBox(QtGui.QMessageBox.Information,
					title, "Info: %s" % (str))
				msgBox.exec_()
	elif level == logging.WARN:
		if settings.TArg:
			logger.warning(str)
		elif guiExists:
			logger.warning(str)
			if logger.getEffectiveLevel() <= level:
				dialog.appendDescription("<br>Warning: %s" %	(str))
		else:
			logger.warning(str)
			if logger.getEffectiveLevel() <= level:
				msgBox = QtGui.QMessageBox(QtGui.QMessageBox.Warning,
					title, "Warning: %s" % (str))
				msgBox.exec_()
	elif level == logging.ERROR:
		if settings.TArg:
			logger.error(str)
		elif guiExists:
			logger.error(str)
			if logger.getEffectiveLevel() <= level:
				dialog.appendDescription("<br>Error: %s" %	(str))
		else:
			logger.error(str)
			if logger.getEffectiveLevel() <= level:
				msgBox = QtGui.QMessageBox(QtGui.QMessageBox.Critical,
					title, "Error: %s" % (str))
				msgBox.exec_()
	elif level == logging.CRITICAL:
		if settings.TArg:
			logger.critical(str)
		elif guiExists:
			logger.critical(str)
			if logger.getEffectiveLevel() <= level:
				dialog.appendDescription("<br>Critical: %s" %	(str))
		else:
			logger.critical(str)
			if logger.getEffectiveLevel() <= level:
				msgBox = QtGui.QMessageBox(QtGui.QMessageBox.Critical,
					title, "Critical: %s" % (str))
				msgBox.exec_()
	if dialog is not None:
		# move the cursor to the end of the text, scroll to the bottom
		cursor = dialog.textBrowser.textCursor()
		cursor.setPosition(len(dialog.textBrowser.toPlainText()))
		dialog.textBrowser.ensureCursorVisible()
		dialog.textBrowser.setTextCursor(cursor)

def analyzeFilename(inputFile, settings, logger, dialog):
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

	@param inputFile: filename
	"""
	reportLogging("Analyzing filename %s" % inputFile, logging.DEBUG,
		"Debug", settings, logger, dialog)
	head, tail = os.path.split(inputFile)

	if '.' in tail:
		if tail.endswith(basics.TSFEFILEEXT):
			return("d")
		else:
			return("e")
	else:
		if (len(tail) % 16 == 0) and (re.search(r'[^\-_a-zA-Z0-9]', tail) is None) and (re.search(r'[^\A-P]', tail[-1:]) is None):
			return("d")
		else:
			return("e")

def decryptFileNameOnly(inputFile, settings, fileMap, logger, dialog):
	"""
	Decrypt a filename.
	If it ends with .tsfe then the filename is plain text
	Otherwise the filename is obfuscated.

	@param inputFile: filename
	"""
	reportLogging("Decrypting filename %s" % inputFile, logging.DEBUG,
		"Debug", settings, logger, dialog)
	head, tail = os.path.split(inputFile)

	if tail.endswith(basics.TSFEFILEEXT) or (not ((len(tail) % 16 == 0) and \
			(re.search(r'[^\-_a-zA-Z0-9]', tail) is None) and (re.search(r'[^\A-P]', tail[-1:]) is None))):
		isObfuscated = False
		if tail.endswith(basics.TSFEFILEEXT):
			plaintextfname = inputFile[:-len(basics.TSFEFILEEXT)]
		else:
			plaintextfname = inputFile
	else:
		isObfuscated = True
		plaintextfname = os.path.join(head, fileMap.deobfuscateFilename(tail))

	phead, ptail = os.path.split(plaintextfname)
	if not isObfuscated:
		reportLogging("Plaintext filename/path: \"%s\"" % plaintextfname,
			logging.DEBUG, "Filename deobfuscation", settings, logger, dialog)
		reportLogging("Filename/path \"%s\" is already in plaintext." % tail,
			logging.INFO, "Filename deobfuscation", settings, logger, dialog)
	else:
		reportLogging("Encrypted filename/path: \"%s\"" % inputFile,
			logging.DEBUG, "Filename deobfuscation", settings, logger, dialog)
		reportLogging("Plaintext filename/path: \"%s\"" % plaintextfname,
			logging.DEBUG, "Filename deobfuscation", settings, logger, dialog)
		reportLogging("Plaintext filename of \"%s\" is \"%s\"." %
			(tail, ptail), logging.NOTSET,
			"Filename deobfuscation", settings, logger, dialog)
	return plaintextfname

def decryptFile(inputFile, settings, fileMap, logger, dialog):
	"""
	Decrypt a file.
	If it ends with .tsfe then the filename is plain text
	Otherwise the filename is obfuscated.

	@param inputFile: filename of encrypted file
	"""
	reportLogging("Decrypting file %s" % inputFile, logging.DEBUG,
		"Debug", settings, logger, dialog)
	head, tail = os.path.split(inputFile)

	if not os.path.isfile(inputFile):
		reportLogging("File \"%s\" does not exist, is not a proper file, "
			"or is a directory. Skipping it." % inputFile, logging.ERROR,
			"File IO Error", settings, logger, dialog)
		return
	else:
		if not os.access(inputFile, os.R_OK):
			reportLogging("File \"%s\" cannot be read. No read permissions. "
				"Skipping it." % inputFile, logging.ERROR, "File IO Error",
				settings, logger, dialog)
			return

	if tail.endswith(basics.TSFEFILEEXT):
		isEncrypted = True
	elif ((len(tail) % 16 == 0) and \
			(re.search(r'[^\-_a-zA-Z0-9]', tail) is None) and (re.search(r'[^\A-P]', tail[-1:]) is None)):
		isEncrypted = True
	else:
		isEncrypted = False

	if not isEncrypted:
		reportLogging("File/path seems plaintext: \"%s\"" % inputFile,
			logging.DEBUG, "File decryption", settings, logger, dialog)
		reportLogging("File \"%s\" seems to be already in plaintext. "
			"Decrypting a plaintext file will fail. Skipping file." % tail,
			logging.WARNING, "File decryption", settings, logger, dialog)
		return None
	else:
		outputfname = fileMap.createDecFile(inputFile)
		# for safety make decrypted file rw to user only
		os.chmod(outputfname, stat.S_IRUSR | stat.S_IWUSR )
		ohead, otail = os.path.split(outputfname)
		reportLogging("Encrypted file/path: \"%s\"" % inputFile,
			logging.DEBUG, "File decryption", settings, logger, dialog)
		reportLogging("Decrypted file/path: \"%s\"" % outputfname,
			logging.DEBUG, "File decryption", settings, logger, dialog)
		reportLogging("File \"%s\" has been decrypted successfully. "
			"Decrypted file \"%s\" was produced." % (tail, otail),
			logging.NOTSET, "File decryption", settings, logger, dialog)
		if os.path.isfile(inputFile) and settings.WArg and settings.DArg:
			# encrypted files are usually read-only, make rw before shred
			os.chmod(inputFile, stat.S_IRUSR | stat.S_IWUSR )
			shred(inputFile, 3, settings, logger, dialog)
	return outputfname

def encryptFileNameOnly(inputFile, settings, fileMap, logger, dialog):
	"""
	Encrypt a filename.
	Show only what the obfuscated filename would be, without encrypting the file
	"""
	reportLogging("Encrypting filename %s" % inputFile, logging.DEBUG,
		"Debug", settings, logger, dialog)
	head, tail = os.path.split(inputFile)

	if analyzeFilename(inputFile, settings, logger, dialog) == "d":
		reportLogging("Filename/path seems decrypted: \"%s\"" % inputFile,
			logging.DEBUG, "File decryption", settings, logger, dialog)
		reportLogging("Filename/path \"%s\" looks like an encrypted file. "
			"Why would you encrypt its filename? This looks strange." % tail,
			logging.WARNING, "Filename obfuscation", settings, logger, dialog)

	obfFileName = os.path.join(head, fileMap.obfuscateFilename(tail))

	ohead, otail = os.path.split(obfFileName)
	reportLogging("Plaintext filename/path: \"%s\"" % inputFile,
		logging.DEBUG, "Filename obfuscation", settings, logger, dialog)
	reportLogging("Obfuscated filename/path: \"%s\"" % obfFileName,
		logging.DEBUG, "Filename obfuscation", settings, logger, dialog)
	# Do not modify or remove the next line.
	# The test harness, the test shell script requires it.
	reportLogging("Obfuscated filename/path of \"%s\" is \"%s\"." % (tail, otail),
		logging.NOTSET, "Filename obfuscation", settings, logger, dialog)
	return obfFileName

def encryptFile(inputFile, settings, fileMap, obfuscate, twice, logger, dialog):
	"""
	Encrypt a file.
	if obfuscate == false then keep the output filename in plain text and add .tsfe

	@param inputFile: filename
	@param fileMap
	@param obfuscate: bool to indicate if an obfuscated filename (True) is
		desired or a plaintext filename (False)
	"""
	reportLogging("Encrypting file %s" % inputFile, logging.DEBUG,
		"Debug", settings, logger, dialog)
	originalFilename = inputFile
	head, tail = os.path.split(inputFile)

	if not os.path.isfile(inputFile):
		reportLogging("File \"%s\" does not exist, is not a proper file, "
			"or is a directory. Skipping it." % inputFile, logging.ERROR,
			"File IO Error", settings, logger, dialog)
		return
	else:
		if not os.access(inputFile, os.R_OK):
			reportLogging("File \"%s\" cannot be read. No read permissions. "
				"Skipping it." % inputFile, logging.ERROR, "File IO Error",
				settings, logger, dialog)
			return

	if (os.path.getsize(inputFile) > 8388608) and twice: # 8M+ and -2 option
		reportLogging("This will take more than 10 minutes. Are you sure "
			"you want to wait? En/decrypting each Megabyte on the Trezor "
			"(model 1) takes about 75 seconds, or 0.8MB/min. The file \"%s\" "
			"would take about %d minutes. If you want to en/decrypt fast "
			"remove the `-2` or `--twice` option." %
			(tail, os.path.getsize(inputFile) / 819200),
			logging.WARNING, "Filename obfuscation",
			settings, logger, dialog) # 800K/min

	if tail.endswith(basics.TSFEFILEEXT):
		isEncrypted = True
	elif ((len(tail) % 16 == 0) and \
			(re.search(r'[^\-_a-zA-Z0-9]', tail) is None) and (re.search(r'[^\A-P]', tail[-1:]) is None)):
		isEncrypted = True
	else:
		isEncrypted = False

	if isEncrypted:
		reportLogging("File/path seems encrypted: \"%s\"" % inputFile,
			logging.DEBUG, "File encryption", settings, logger, dialog)
		reportLogging("File \"%s\" seems to be encrypted already. "
			"Are you sure you want to (possibly) encrypt it again?" % tail,
			logging.WARNING, "File enncryption", settings, logger, dialog)

	outputfname = fileMap.createEncFile(inputFile, obfuscate, twice)
	# for safety make encrypted file read-only
	os.chmod(outputfname, stat.S_IRUSR)
	ohead, otail = os.path.split(outputfname)
	reportLogging("Plaintext file/path: \"%s\"" % inputFile,
		logging.DEBUG, "File encryption", settings, logger, dialog)
	reportLogging("Encrypted file/path: \"%s\"" % outputfname,
		logging.DEBUG, "File encryption", settings, logger, dialog)
	if twice:
		twicetext = " twice"
	else:
		twicetext = ""
	reportLogging("File \"%s\" has been encrypted successfully%s. Encrypted "
		"file \"%s\" was produced." % (tail,twicetext,otail), logging.NOTSET,
		"File encryption", settings, logger, dialog)
	safe = True
	if settings.SArg:
		safe = safetyCheck(inputFile, outputfname, fileMap, settings, logger, dialog)
	if safe and settings.WArg and settings.EArg:
		shred(inputFile, 3, settings, logger, dialog)
	return outputfname

def	safetyCheck(plaintextFname, encryptedFname, fileMap, settings, logger, dialog):
	"""
	check if previous encryption worked by
	renaming plaintextFname file to plaintextFname.<random number>.org
	decrypting file named encryptedFname producing new file decryptedFname
	comparing/diffing decryptedFname to original file now named plaintextFname.<random number>.org
	removing decrypted file decryptedFname
	renaming original file plaintextFname.<random number>.org back to input plaintextFname

	@returns True if safety check passes successfuly
	"""
	urandom_entropy = os.urandom(64)
	randomBin = hashlib.sha256(urandom_entropy).digest()
	# base85 encoding not yet implemented in Python 2.7, (requires Python 3+)
	# so we use base64 encoding
	# replace the base64 buffer char =
	randomB64 = base64.urlsafe_b64encode(randomBin).replace("=", "-")
	originalFname = plaintextFname + "." + randomB64 + ".orignal"
	os.rename(plaintextFname, originalFname)
	decryptedFname = decryptFile(encryptedFname, settings, fileMap, logger, dialog)
	aresame = filecmp.cmp(decryptedFname, originalFname, shallow=False)
	ihead, itail = os.path.split(plaintextFname)
	ohead, otail = os.path.split(encryptedFname)
	if aresame:
		reportLogging("Safety check of file \"%s\" (\"%s\") was successful." %
			(otail,itail),
			logging.INFO, "File encryption", settings, logger, dialog)
	else:
		reportLogging("Fatal error: Safety check of file \"%s\" (\"%s\") failed! "
			"You must inestigate. Encryption was flawed!" %
			(otail,itail),
			logging.CRITICAL, "File encryption", settings, logger, dialog)
	os.remove(decryptedFname)
	os.rename(originalFname, plaintextFname)
	return aresame

def convertFile(inputFile, settings, fileMap, logger, dialog):
	"""
	Encrypt or decrypt one file.

	@param inputFile: filename
	"""
	if settings.DArg:
		# decrypt by choice
		decryptFile(inputFile, settings, fileMap, logger, dialog)
	elif settings.MArg:
		# encrypt (name only) by choice
		encryptFileNameOnly(inputFile, settings, fileMap, logger, dialog)
	elif settings.NArg:
		# decrypt (name only) by choice
		decryptFileNameOnly(inputFile, settings, fileMap, logger, dialog)
	elif settings.EArg and settings.OArg:
		# encrypt and obfuscate by choice
		encryptFile(inputFile, settings, fileMap, True, settings.XArg, logger, dialog)
	elif settings.EArg and not settings.OArg:
		# encrypt by choice
		encryptFile(inputFile, settings, fileMap, False, settings.XArg, logger, dialog)
	else:
		hint = analyzeFilename(inputFile, settings, logger, dialog)
		if hint == "d":
			# decrypt by default
			settings.DArg = True
			decryptFile(inputFile, settings, fileMap, logger, dialog)
			settings.DArg = False
		else:
			# encrypt by default
			settings.EArg = True
			encryptFile(inputFile, settings, fileMap, False, settings.XArg, logger, dialog)
			settings.EArg = False

def doWork(trezor, settings, fileMap, logger, dialog):
	reportLogging("Time entering doWork(): %s" % datetime.datetime.now(),
		logging.DEBUG, "Debug", settings, logger, dialog)
	for inputFile in settings.inputFiles:
		try:
			reportLogging("Working on file: %s" % inputFile,
				logging.DEBUG, "Debug", settings, logger, dialog)
			convertFile(inputFile, settings, fileMap, logger, dialog)
		except PinException:
			msgBox = QtGui.QMessageBox(text="Invalid PIN")
			msgBox.exec_()
			sys.exit(8)
		except CallException:
			#button cancel on Trezor, so exit
			sys.exit(6)
		except IOError, e:
			reportLogging("IO error: %s" % e, logging.CRITICAL,
				"Critical Exception", settings, logger, dialog)
			traceback.print_exc() # prints to stderr
		except Exception, e:
			reportLogging("Critical error: %s" % e, logging.CRITICAL,
				"Critical Exception", settings, logger, dialog)
			traceback.print_exc() # prints to stderr
	reportLogging("Time leaving doWork(): %s" % datetime.datetime.now(),
		logging.DEBUG, "Debug", settings, logger, dialog)

def processAllFromApply(dialog, trezor, settings, fileMap, logger):
	settings.gui2Settings(dialog,trezor)
	reportLogging("Apply button was clicked",
		logging.DEBUG, "Debug", settings, logger, dialog)
	processAll(trezor, settings, fileMap, logger, dialog)
	reportLogging("Apply button was processed, returning to GUI",
		logging.DEBUG, "Debug", settings, logger, dialog)

def processAll(trezor, settings, fileMap, logger, dialog=None):
	doWork(trezor, settings, fileMap, logger, dialog)
