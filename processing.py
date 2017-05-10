import sys
import struct
import logging
import getopt
import re
import datetime
import traceback
import os.path

from PyQt4 import QtCore
from PyQt4 import QtGui


from trezorlib.client import CallException, PinException

from encoding import q2s, s2q
import basics


class Feedback(object):
	"""
	string reported back to the GUI and displayed in the Status textarea of the GUI
	"""
	def __init__(self):
		self.feedback = "" # html formatted string with <br> as linebreaks

	def addFeedback(self,fb):
		self.feedback += fb

	def setFeedback(self,fb):
		self.feedback = fb

	def getFeedback(self):
		return self.feedback

	def clearFeedback(self):
		self.feedback = ""

class Settings(object):
	"""
	Settings, command line options, GUI selected values
	"""

	def __init__(self, logger):
		self.logger = logger
		self.guiExists = False
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
		self.inputFiles = [] # list of input filenames

	def printSettings(self):
		self.logger.debug("self.guiExists = %s", self.guiExists)
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
		self.logger.debug("self.inputFiles = %s", str(self.inputFiles))

	def gui2Settings(self, dialog, trezor):
		trezor.prefillPassphrase(q2s(dialog.pw1()))
		self.DArg = dialog.dec()
		self.NArg = dialog.decFn()
		self.EArg = dialog.enc() and not dialog.encTwice() and not dialog.encObf()
		self.OArg = dialog.encObf() or dialog.encTwiceObf()
		self.XArg = dialog.encTwice() or dialog.encTwiceObf()
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
		dialog.setEnc(self.EArg and not self.OArg and not self.XArg)
		dialog.setEncObf(self.OArg and not self.XArg)
		dialog.setEncTwice(self.XArg and self.EArg and not self.OArg)
		dialog.setEncTwiceObf(self.XArg and self.EArg and self.OArg)
		dialog.setPw1(self.PArg)
		dialog.setPw2(self.PArg)
		self.printSettings()

def usage():
	print """TrezorSymmetricFileEncryption.py [-v] [-h] [-l <level>] [-t] [-2] [-o | -e | -d | -n] [-p <passphrase>] <files>
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
		"""

def printVersion():
	print "Version: " + basics.TSFEVERSION

def parseArgs(argv, settings, logger):
	try:
		opts, args = getopt.getopt(argv,"vhl:tmn2deop:",
			["version","help","logging=","terminal","encnameonly","decnameonly",
			"twice","decrypt","encrypt","obfuscatedencrypt","passphrase="])
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
	if settings.EArg and settings.OArg:
		settings.EArg = False # if both E and O are set we default to O
	if settings.MArg:
		settings.EArg = False
		settings.OArg = False
	if settings.NArg:
		settings.DArg = False
	settings.inputFiles = args
	logger.debug("Specified files are: %s", str(args))
	settings.printSettings()

def reportLogging(str, level, title, settings, logger, feedback=None):
	"""
	Displays string str depending on scenario:
	a) in terminal mode: thru logger (except if loglevel == NOTSET)
	b) in GUI mode and GUI window open: in Status textarea of GUI window
	c) in GUI mode but window already closed: thru QMessageBox()

	@param str: string to report/log
	@param level: log level from DEBUG to CRITICAL
	@param title: window title text
	"""
	if feedback == None:
		guiExists = False
	else:
		guiExists = settings.guiExists
	if level == logging.NOTSET:
		if settings.TArg:
			print str # stdout
		elif guiExists:
			print str # stdout
			feedback.addFeedback("<br>%s" %	(str))
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
				feedback.addFeedback("<br>Debug: %s" %	(str))
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
				feedback.addFeedback("<br>Info: %s" %	(str))
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
				feedback.addFeedback("<br>Warning: %s" %	(str))
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
				feedback.addFeedback("<br>Error: %s" %	(str))
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
				feedback.addFeedback("<br>Critical: %s" %	(str))
		else:
			logger.critical(str)
			if logger.getEffectiveLevel() <= level:
				msgBox = QtGui.QMessageBox(QtGui.QMessageBox.Critical,
					title, "Critical: %s" % (str))
				msgBox.exec_()

def analyzeFilename(inputFile, settings, logger, feedback):
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
		"Debug", settings, logger, feedback)
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

def decryptFileNameOnly(inputFile, settings, fileMap, logger, feedback):
	"""
	Decrypt a filename.
	If it ends with .tsfe then the filename is plain text
	Otherwise the filename is obfuscated.

	@param inputFile: filename
	"""
	reportLogging("Decrypting filename %s" % inputFile, logging.DEBUG,
		"Debug", settings, logger, feedback)
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
			logging.DEBUG, "Filename deobfuscation", settings, logger, feedback)
		reportLogging("Filename/path \"%s\" is already in plaintext." % tail,
			logging.INFO, "Filename deobfuscation", settings, logger, feedback)
	else:
		reportLogging("Encrypted filename/path: \"%s\"" % inputFile,
			logging.DEBUG, "Filename deobfuscation", settings, logger, feedback)
		reportLogging("Plaintext filename/path: \"%s\"" % plaintextfname,
			logging.DEBUG, "Filename deobfuscation", settings, logger, feedback)
		reportLogging("Plaintext filename of \"%s\" is \"%s\"." %
			(tail, ptail), logging.NOTSET,
			"Filename deobfuscation", settings, logger, feedback)

def decryptFile(inputFile, settings, fileMap, logger, feedback):
	"""
	Decrypt a file.
	If it ends with .tsfe then the filename is plain text
	Otherwise the filename is obfuscated.

	@param inputFile: filename of encrypted file
	"""
	reportLogging("Decrypting file %s" % inputFile, logging.DEBUG,
		"Debug", settings, logger, feedback)
	head, tail = os.path.split(inputFile)

	if not os.path.isfile(inputFile):
		reportLogging("File \"%s\" does not exist, is not a proper file, "
			"or is a directory. Skipping it." % inputFile, logging.ERROR,
			"File IO Error", settings, logger, feedback)
		return
	else:
		if not os.access(inputFile, os.R_OK):
			reportLogging("File \"%s\" cannot be read. No read permissions. "
				"Skipping it." % inputFile, logging.ERROR, "File IO Error",
				settings, logger, feedback)
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
			logging.DEBUG, "File decryption", settings, logger, feedback)
		reportLogging("File \"%s\" seems to be already in plaintext. "
			"Decrypting a plaintext file will fail. Skipping file." % tail,
			logging.WARNING, "File decryption", settings, logger, feedback)
	else:
		outputfname = fileMap.createDecFile(inputFile)
		ohead, otail = os.path.split(outputfname)
		reportLogging("Encrypted file/path: \"%s\"" % inputFile,
			logging.DEBUG, "File decryption", settings, logger, feedback)
		reportLogging("Decrypted file/path: \"%s\"" % outputfname,
			logging.DEBUG, "File decryption", settings, logger, feedback)
		reportLogging("File \"%s\" has been decrypted successfully. "
			"Decrypted file \"%s\" was produced." % (tail, otail),
			logging.NOTSET, "File decryption", settings, logger, feedback)

def encryptFileNameOnly(inputFile, settings, fileMap, logger, feedback):
	"""
	Encrypt a filename.
	Show only what the obfuscated filename would be, without encrypting the file
	"""
	reportLogging("Encrypting filename %s" % inputFile, logging.DEBUG,
		"Debug", settings, logger, feedback)
	head, tail = os.path.split(inputFile)

	if analyzeFilename(inputFile, settings, logger, feedback) == "d":
		reportLogging("Filename/path seems decrypted: \"%s\"" % inputFile,
			logging.DEBUG, "File decryption", settings, logger, feedback)
		reportLogging("Filename/path \"%s\" looks like an encrypted file. "
			"Why would you encrypt its filename? This looks strange." % tail,
			logging.WARNING, "Filename obfuscation", settings, logger, feedback)

	obfFileName = os.path.join(head, fileMap.obfuscateFilename(tail))

	ohead, otail = os.path.split(obfFileName)
	reportLogging("Plaintext filename/path: \"%s\"" % inputFile,
		logging.DEBUG, "Filename obfuscation", settings, logger, feedback)
	reportLogging("Obfuscated filename/path: \"%s\"" % obfFileName,
		logging.DEBUG, "Filename obfuscation", settings, logger, feedback)
	# Do not modify or remove the next line.
	# The test harness, the test shell script requires it.
	reportLogging("Obfuscated filename/path of \"%s\" is \"%s\"." % (tail, otail),
			logging.NOTSET, "Filename obfuscation", settings, logger, feedback)

def encryptFile(inputFile, settings, fileMap, obfuscate, twice, logger, feedback):
	"""
	Encrypt a file.
	if obfuscate == false then keep the output filename in plain text and add .tsfe

	@param inputFile: filename
	@param fileMap
	@param obfuscate: bool to indicate if an obfuscated filename (True) is
		desired or a plaintext filename (False)
	"""
	reportLogging("Encrypting file %s" % inputFile, logging.DEBUG,
		"Debug", settings, logger, feedback)
	originalFilename = inputFile
	head, tail = os.path.split(inputFile)

	if not os.path.isfile(inputFile):
		reportLogging("File \"%s\" does not exist, is not a proper file, "
			"or is a directory. Skipping it." % inputFile, logging.ERROR,
			"File IO Error", settings, logger, feedback)
		return
	else:
		if not os.access(inputFile, os.R_OK):
			reportLogging("File \"%s\" cannot be read. No read permissions. "
				"Skipping it." % inputFile, logging.ERROR, "File IO Error",
				settings, logger, feedback)
			return

	if (os.path.getsize(inputFile) > 8388608) and twice: # 8M+ and -2 option
		reportLogging("This will take more than 10 minutes. Are you sure "
			"you want to wait? En/decrypting each Megabyte on the Trezor "
			"(model 1) takes about 75 seconds, or 0.8MB/min. The file \"%s\" "
			"would take about %d minutes. If you want to en/decrypt fast "
			"remove the `-2` or `--twice` option." %
			(tail, os.path.getsize(inputFile) / 819200),
			logging.WARNING, "Filename obfuscation",
			settings, logger, feedback) # 800K/min

	if tail.endswith(basics.TSFEFILEEXT):
		isEncrypted = True
	elif ((len(tail) % 16 == 0) and \
			(re.search(r'[^\-_a-zA-Z0-9]', tail) is None) and (re.search(r'[^\A-P]', tail[-1:]) is None)):
		isEncrypted = True
	else:
		isEncrypted = False

	if isEncrypted:
		reportLogging("File/path seems encrypted: \"%s\"" % inputFile,
			logging.DEBUG, "File encryption", settings, logger, feedback)
		reportLogging("File \"%s\" seems to be encrypted already. "
			"Are you sure you want to (possibly) encrypt it again?" % tail,
			logging.WARNING, "File enncryption", settings, logger, feedback)

	outputfname = fileMap.createEncFile(inputFile, obfuscate, twice)
	ohead, otail = os.path.split(outputfname)
	reportLogging("Plaintext file/path: \"%s\"" % inputFile,
		logging.DEBUG, "File encryption", settings, logger, feedback)
	reportLogging("Encrypted file/path: \"%s\"" % outputfname,
		logging.DEBUG, "File encryption", settings, logger, feedback)
	reportLogging("File \"%s\" has been encrypted successfully. Encrypted "
		"file \"%s\" was produced." % (tail,otail), logging.NOTSET,
		"File encryption", settings, logger, feedback)

def convertFile(inputFile, settings, fileMap, logger, feedback):
	"""
	Encrypt or decrypt one file.

	@param inputFile: filename
	"""
	if settings.DArg:
		# decrypt by choice
		decryptFile(inputFile, settings, fileMap, logger, feedback)
	elif settings.MArg:
		# encrypt (name only) by choice
		encryptFileNameOnly(inputFile, settings, fileMap, logger, feedback)
	elif settings.NArg:
		# decrypt (name only) by choice
		decryptFileNameOnly(inputFile, settings, fileMap, logger, feedback)
	elif settings.OArg:
		# encrypt and obfuscate by choice
		encryptFile(inputFile, settings, fileMap, True, settings.XArg, logger, feedback)
	elif settings.EArg:
		# encrypt by choice
		encryptFile(inputFile, settings, fileMap, False, settings.XArg, logger, feedback)
	else:
		hint = analyzeFilename(inputFile, settings, logger, feedback)
		if hint == "d":
			# decrypt by default
			decryptFile(inputFile, settings, fileMap, logger, feedback)
		else:
			# encrypt by default
			encryptFile(inputFile, settings, fileMap, False, settings.XArg, logger, feedback)

def doWork(trezor, settings, fileMap, logger, feedback):
	reportLogging("Time entering doWork(): %s" % datetime.datetime.now(),
		logging.DEBUG, "Debug", settings, logger, feedback)
	for inputFile in settings.inputFiles:
		try:
			reportLogging("Working on file: %s" % inputFile,
				logging.DEBUG, "Debug", settings, logger, feedback)
			convertFile(inputFile, settings, fileMap, logger, feedback)
		except PinException:
			msgBox = QtGui.QMessageBox(text="Invalid PIN")
			msgBox.exec_()
			sys.exit(8)
		except CallException:
			#button cancel on Trezor, so exit
			sys.exit(6)
		except Exception, e:
			reportLogging(e.message, logging.CRITICAL,
				"Critical Exception", settings, logger, feedback)
			traceback.print_exc() # prints to stderr
	reportLogging("Time leaving doWork(): %s" % datetime.datetime.now(),
		logging.DEBUG, "Debug", settings, logger, feedback)

def processAllFromApply(dialog, trezor, settings, fileMap, logger):
	settings.gui2Settings(dialog,trezor)
	feedback = Feedback()
	reportLogging("Apply button was clicked",
		logging.DEBUG, "Debug", settings, logger, feedback)
	processAll(trezor, settings, fileMap, logger, feedback)
	reportLogging("Apply button was processed, returning to GUI",
		logging.DEBUG, "Debug", settings, logger, feedback)
	return feedback.getFeedback()

def processAll(trezor, settings, fileMap, logger, feedback):
	doWork(trezor, settings, fileMap, logger, feedback)
