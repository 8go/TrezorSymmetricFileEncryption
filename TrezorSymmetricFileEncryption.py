#!/usr/bin/env python

'''
Use TREZOR as a hardware device for symmetric file encryption

Usage: python TrezorSymmetricFileEncryption.py [-v] [-h] [-o | -e | -d] <files>

Source and readme is on www.github.com, search for TrezorSymmetricFileEncryption

'''

import sys
import getopt
import logging
import os.path
import csv
import time
import traceback
import re
import datetime

from PyQt4 import QtGui, QtCore
from PyQt4.QtCore import QTimer
from PyQt4.QtGui import QPixmap
from Crypto import Random
from shutil import copyfile

from trezorlib.client import BaseClient, ProtocolMixin, CallException, PinException
from trezorlib.transport import ConnectionError
from trezorlib.transport_hid import HidTransport
from trezorlib import messages_pb2 as proto

import file_map
from encoding import q2s, s2q

from dialogs import TrezorPassphraseDialog, Dialog, EnterPinDialog, TrezorChooserDialog

import basics

class QtTrezorMixin(object):
	"""
	Mixin for input of passhprases.
	"""

	def __init__(self, *args, **kwargs):
		super(QtTrezorMixin, self).__init__(*args, **kwargs)
		self.passphrase = None

	def callback_ButtonRequest(self, msg):
		return proto.ButtonAck()

	def callback_PassphraseRequest(self, msg):
		if self.passphrase is not None:
			return proto.PassphraseAck(passphrase=self.passphrase)

		dialog = TrezorPassphraseDialog()
		if not dialog.exec_():
			sys.exit(3)
		else:
			passphrase = dialog.passphraseEdit.text()
			passphrase = unicode(passphrase)

		return proto.PassphraseAck(passphrase=passphrase)

	def callback_PinMatrixRequest(self, msg):
		dialog = EnterPinDialog()
		if not dialog.exec_():
			sys.exit(7)

		pin = q2s(dialog.pin())
		return proto.PinMatrixAck(pin=pin)

	def prefillPassphrase(self, passphrase):
		"""
		Instead of asking for passphrase, use this one
		"""
		self.passphrase = passphrase.decode("utf-8")

class QtTrezorClient(ProtocolMixin, QtTrezorMixin, BaseClient):
	"""
	Trezor client with Qt input methods
	"""
	pass

class TrezorChooser(object):
	"""Class for working with Trezor device via HID"""

	def __init__(self):
		pass

	def getDevice(self):
		"""
		Get one from available devices. Widget will be shown if more
		devices are available.
		"""
		devices = self.enumerateHIDDevices()

		if not devices:
			return None

		transport = self.chooseDevice(devices)
		client = QtTrezorClient(transport)

		return client

	def enumerateHIDDevices(self):
		"""Returns Trezor HID devices"""
		devices = HidTransport.enumerate()

		return devices

	def chooseDevice(self, devices):
		"""
		Choose device from enumerated list. If there's only one Trezor,
		that will be chosen.

		If there are multiple Trezors, diplays a widget with list
		of Trezor devices to choose from.

		@returns HidTransport object of selected device
		"""
		if not len(devices):
			raise RuntimeError("No Trezor connected!")

		if len(devices) == 1:
			try:
				return HidTransport(devices[0])
			except IOError:
				raise RuntimeError("Trezor is currently in use")


		#maps deviceId string to device label
		deviceMap = {}
		for device in devices:
			try:
				transport = HidTransport(device)
				client = QtTrezorClient(transport)
				label = client.features.label and client.features.label or "<no label>"
				client.close()

				deviceMap[device[0]] = label
			except IOError:
				#device in use, do not offer as choice
				continue

		if not deviceMap:
			raise RuntimeError("All connected Trezors are in use!")

		dialog = TrezorChooserDialog(deviceMap)
		if not dialog.exec_():
			sys.exit(9)

		deviceStr = dialog.chosenDeviceStr()
		return HidTransport([deviceStr, None])


class Settings(object):
	"""
	Settings, command line options, GUI selected values
	"""

	def __init__(self):
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
		logger.debug("self.VArg = %s", self.VArg)
		logger.debug("self.HArg = %s", self.HArg)
		logger.debug("self.TArg = %s", self.TArg)
		logger.debug("self.EArg = %s", self.EArg)
		logger.debug("self.OArg = %s", self.OArg)
		logger.debug("self.DArg = %s", self.DArg)
		logger.debug("self.MArg = %s", self.MArg)
		logger.debug("self.NArg = %s", self.NArg)
		logger.debug("self.XArg = %s", self.XArg)
		logger.debug("self.PArg = %s", self.PArg)
		logger.debug("self.inputFiles = %s", str(self.inputFiles))

def showGui(trezor, settings):
	"""
	Initialize, ask for encrypt/decrypt options,
	ask for files to be decrypted/encrypted,
	ask for master passphrase = trezor passphrase.

	Makes sure a session is created on Trezor so that the passphrase
	will be cached until disconnect.

	@param trezor: Trezor client
	@param settings: Settings object to store command line arguments or items selected in GUI
	"""
	dialog = Dialog()
	dialog.setVersion(basics.TSFEVERSION)
	dialog.setDescription("")
	dialog.setSelectedFile(settings.inputFiles)
	dialog.setSelectedFiles(settings.inputFiles)
	settings.printSettings()
	dialog.setDec(settings.DArg)
	dialog.setDecFn(settings.NArg)
	dialog.setEnc(settings.EArg)
	dialog.setEncObf(settings.OArg)
	dialog.setPw1(settings.PArg)
	dialog.setPw2(settings.PArg)
	if not dialog.exec_():
		sys.exit(4)

	masterPassphrase = q2s(dialog.pw1())

	trezor.prefillPassphrase(masterPassphrase)
	settings.DArg = dialog.dec()
	settings.NArg = dialog.decFn()
	settings.EArg = dialog.enc()
	settings.OArg = dialog.encObf()
	settings.PArg = dialog.pw1()
	settings.inputFiles = dialog.selectedFiles()
	settings.printSettings()

def usage():
	print """TrezorSymmetricFileEncryption.py [-v] [-h] [-l <level>] [-t] [-2] [-o | -e | -d | -n] [-p <passphrase>] <files>
		-v, --verion          ... optional ... print the version number
		-h, --help            ... optional ... print short help text
		-l, --logging         ... optional ... set logging level, integer from 1 to 5, 1=full logging, 5=no logging
		-t, --terminal        ... optional ... run in the terminal, except for PIN query
	                                           and possibly a Passphrase query this avoids the GUI
		-m, --encnameonly     ... optional ... just encrypt the plaintext filename, show what the obfuscated filename would be
	                                           does not encrypt the file itself, incompaible with `-d` and `-n`
		-n, --decnameonly     ... optional ... just decrypt the obfuscated filename,
	                                           does not decrypt the file itself, incompaible with `-o`, `-e`, and `-m`
		-d, --decrypt         ... optional ... decrypt file
		-e, --encrypt         ... optional ... encrypt file and keep plaintext file name for output (appends .tsfe suffix)
		-o, --obfuscatedencrypt . optional ... encrypt file and obfuscate file name of output
		-2, --twice           ... optional ... paranoid mode; encrypt file a second time on the Trezor chip itself;
                                               only relevant for `-e` and `-o`; ignored in all other cases.
		                                       Consider filesize: The Trezor chip is slow. 1M takes roughly 75 seconds.
		-p, --passphrase      ... optional ... master passphrase used for Trezor
	                                           It is recommended that you do not use this command line option
	                                           but rather give the passphrase through a small window interaction.
		<files>               ...              one or multiple files to be encrypted or decrypted

		By default it will use a GUI.

		You can force it to avoid the GUI by using `-t`, the Terminal mode.
		If you specify filename, possibly some `-o`, `-e`, or `-d` option, then
		only PIN and Passphrase will be collected through windows.

		Using the GUI has the advantage that no passphrase has to be specified in the command line.
		So, using the GUI is safer.

		Most of the time TrezorSymmetricFileEncryption can detect automatically if
		it needs to decrypt or encrypt by analyzing the given input file name.
		So, in most of the cases you do not need to specify any
		de/encryption option.
		TrezorSymmetricFileEncryption will simply do the right thing.
		In the very rare case that TrezorSymmetricFileEncryption determines
		the wrong encrypt/decrypt operation you can force it to use the right one
		by using either `-e` or `-d` or selecting the appropriate option in the GUI.

		If TrezorSymmetricFileEncryption automatically choses the encryption
		option for you, it will chose by default the `-e`, and create
		plaintext encrypted files with an `.tsfe` suffix.

		If you want the output file name to be obfuscated you
		must use the `-o` (obfuscate) flag or select that option in the GUI.

		Be aware of computation time and file sizes when you use `-2` option.
		Encrypting on the Trezor takes time: 1M roughtly 75sec. 50M about 1h.
		Without `-2` a 1G file takes roughly 15 seconds.
		"""

def printVersion():
	print "Version: " + basics.TSFEVERSION

def parseArgs(argv, settings):
	try:
		opts, args = getopt.getopt(argv,"vhl:tmn2deop:",["version","help","logging=","terminal","encnameonly","decnameonly","twice","decrypt","encrypt","obfuscatedencrypt","passphrase="])
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
			if settings.TArg:
				logger.critical('Logging level not specified correctly. Must be integer between 1 and 5. (%s)', loglevelarg)
			else:
				msgBox = QtGui.QMessageBox(QtGui.QMessageBox.Critical, "Wrong arguments", "Error: Logging level not specified correctly. Must be integer between 1 and 5.")
				msgBox.exec_()
			sys.exit()
		if loglevel > 5 or loglevel < 1:
			if settings.TArg:
				logger.critical('Logging level not specified correctly. Must be integer between 1 and 5. (%s)', loglevelarg)
			else:
				msgBox = QtGui.QMessageBox(QtGui.QMessageBox.Critical, "Wrong arguments", "Error: Logging level not specified correctly. Must be integer between 1 and 5.")
				msgBox.exec_()
			sys.exit()
		basics.LOGGINGLEVEL = loglevel * 10 # https://docs.python.org/2/library/logging.html#levels
		logger.setLevel(basics.LOGGINGLEVEL)
		logger.info('Logging level set to %s (%d).', logging.getLevelName(basics.LOGGINGLEVEL), basics.LOGGINGLEVEL)

	if (settings.DArg and settings.EArg) or (settings.DArg and settings.OArg):
		if settings.TArg:
			logger.critical("You cannot specify both decrypt and encrypt. It is one or the other. Either -d or -e or -o.")
		else:
			msgBox = QtGui.QMessageBox(QtGui.QMessageBox.Critical, "Wrong arguments", "Error: You cannot specify both decrypt and encrypt. It is one or the other. Either -d or -e or -o.")
			msgBox.exec_()
		sys.exit(2)
	if (settings.MArg and settings.DArg) or (settings.MArg and settings.NArg):
		if settings.TArg:
			logger.critical("You cannot specify both \"encrypt filename\" and \"decrypt file(name)\". It is one or the other. Don't use -m when using -d or -n (and vice versa).")
		else:
			msgBox = QtGui.QMessageBox(QtGui.QMessageBox.Critical, "Wrong arguments", "Error: You cannot specify both \"encrypt filename\" and \"decrypt file(name)\". It is one or the other. Don't use -m when using -d or -n (and vice versa).")
			msgBox.exec_()
		sys.exit(2)
	if (settings.NArg and settings.EArg) or (settings.NArg and settings.OArg) or (settings.NArg and settings.MArg):
		if settings.TArg:
			logger.critical("You cannot specify both \"decrypt filename\" and \"encrypt file(name)\". It is one or the other. Don't use -n when using -e, -o, or -m (and vice versa).")
		else:
			msgBox = QtGui.QMessageBox(QtGui.QMessageBox.Critical, "Wrong arguments", "Error: You cannot specify both \"decrypt filename\" and \"encrypt file(name)\". It is one or the other. Don't use -n when using -e, -o, or -m (and vice versa).")
			msgBox.exec_()
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

def analyzeFilename(inputFile):
	"""
	Determine from the input filename if we have to Encrypt or decrypt the file.

	Returns "d" or "e" for decrypt, encrypt
	EncryptObfuscate is not a possibility, for EncryptObfuscate the user must use -o option.
	The default if nothing is specified is the normal plaintext encrypt.

	If it ends in .tsfe then return "d" (only encrypted files should end in .tsfe)
	If it does not end in .tsfe and has a . then return "e" (obfuscated filenames cannot contain .)
	No . in filename && ( length % 16 != 16 || filename contains letters like &, @, ^, %, $, etc. || last letter is not in A..Q ) then return "e" (encrypted obfuscated files have filename length mod 16, do not contain special chars except - and _, end in A..Q)
	Else return "d" (no ., length mod 16, no special chars, end in A..P)

	@param inputFile: filename
	"""
	logger.debug("Analyzing file name %s", inputFile)
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

def decryptFileNameOnly(inputFile, fileMap):
	"""
	Decrypt a filename.
	If it ends with .tsfe then the filename is plain text
	Otherwise the filename is obfuscated.

	@param inputFile: filename
	"""
	logger.debug("Decrypting filename %s", inputFile)
	originalFilename = inputFile
	head, tail = os.path.split(inputFile)

	if tail.endswith(basics.TSFEFILEEXT):
		isObfuscated = False
		inputFile = inputFile[:-len(basics.TSFEFILEEXT)]
	else:
		isObfuscated = True
		inputFile = os.path.join(head, fileMap.deobfuscateFilename(tail))

	if not isObfuscated:
		if settings.TArg:
			logger.warning("Filename/path %s is already in plaintext.", inputFile)
		else:
			msgBox = QtGui.QMessageBox(QtGui.QMessageBox.Information, "Filename deobfuscation", "Info: Filename/path of \"%s\" is already in plaintext." % (inputFile))
			msgBox.exec_()
	else:
		if settings.TArg:
			print("Plaintext filename/path of \"%s\" is \"%s\"." % (originalFilename, inputFile))
		else:
			msgBox = QtGui.QMessageBox(QtGui.QMessageBox.Information, "Filename deobfuscation", "Info: Plaintext filename/path of \"%s\" is \"%s\"." % (originalFilename, inputFile))
			msgBox.exec_()
	return

def decryptFile(inputFile, fileMap):
	"""
	Decrypt a file.
	If it ends with .tsfe then the filename is plain text
	Otherwise the filename is obfuscated.

	@param inputFile: filename of encrypted file
	"""
	fileMap.createDecFile(inputFile)

def encryptFileNameOnly(inputFile, fileMap):
	"""
	Encrypt a filename.
	Show only what the obfuscated filename would be, without encrypting the file
	"""
	logger.debug("Encrypting filename %s", inputFile)

	head, tail = os.path.split(inputFile)

	if analyzeFilename(inputFile) == "d":
		if settings.TArg:
			logger.warning("Filename/path \"%s\" looks like an encrypted file. Why would you encrypt its filename? This looks strange.", inputFile)
		else:
			msgBox = QtGui.QMessageBox(QtGui.QMessageBox.Warning, "Filename obfuscation", "Info: Filename/path \"%s\" looks like an encrypted file. Why would you encrypt its filename? This looks strange." % (inputFile))
			msgBox.exec_()

	obfFileName = os.path.join(head, fileMap.obfuscateFilename(tail))

	if settings.TArg:
		# Do not modify or remove the next line.
		# The test harness, the test shell script requires it.
		print("Obfuscated filename/path of \"%s\" is \"%s\"." % (inputFile, obfFileName))
	else:
		msgBox = QtGui.QMessageBox(QtGui.QMessageBox.Information, "Filename obfuscation", "Info: Obfuscated filename/path of \"%s\" is \"%s\"." % (inputFile, obfFileName))
		msgBox.exec_()
	return

def encryptFile(inputFile, fileMap, obfuscate, twice=False):
	"""
	Encrypt a file.
	if obfuscate == false then keep the output filename in plain text and add .tsfe

	@param inputFile: filename
	@param fileMap
	@param obfuscate: bool to indicate if an obfuscated filename (True) is desired or a plaintext filename (False)
	"""
	logger.debug("Encrypting file %s", inputFile)
	if (os.path.getsize(inputFile) > 8388608) and twice: # 8M+ and -2 option
		if settings.TArg:
			logger.warning("This will take more than 10 minutes. Are you sure you want to wait? En/decrypting each Megabyte on the Trezor (model 1) takes about 75 seconds, or 0.8MB/min. The file \"%s\" would take about %d minutes. If you want to en/decrypt fast remove the `-2` or `--twice` option.", inputFile, os.path.getsize(inputFile) / 819200)
		else:
			msgBox = QtGui.QMessageBox(QtGui.QMessageBox.Warning, "Filename obfuscation", "Info: This will take more than 10 minutes. Are you sure you want to wait? En/decrypting each Megabyte on the Trezor (model 1) takes about 75 seconds, or 0.8MB/min. The file \"%s\" would take about %d minutes. If you want to en/decrypt fast remove the `-2` or `--twice` option." % (inputFile, os.path.getsize(inputFile) / 819200))
			msgBox.exec_()
	fileMap.createEncFile(inputFile, obfuscate, twice)

def convertFile(inputFile, fileMap):
	"""
	Encrypt or decrypt one file.

	@param inputFile: filename
	"""
	if settings.DArg:
		# decrypt by choice
		decryptFile(inputFile, fileMap)
	elif settings.MArg:
		# encrypt (name only) by choice
		encryptFileNameOnly(inputFile, fileMap)
	elif settings.NArg:
		# decrypt (name only) by choice
		decryptFileNameOnly(inputFile, fileMap)
	elif settings.OArg:
		# encrypt and obfuscate by choice
		encryptFile(inputFile, fileMap, True, settings.XArg)
	elif settings.EArg:
		# encrypt by choice
		encryptFile(inputFile, fileMap, False, settings.XArg)
	else:
		hint = analyzeFilename(inputFile)
		if hint == "d":
			# decrypt by default
			decryptFile(inputFile, fileMap)
		else:
			# encrypt by default
			encryptFile(inputFile, fileMap, False, settings.XArg)


def doWork(trezor, settings, fileMap):
	logger.debug('time entering doWork: %s', datetime.datetime.now())
	for inputFile in settings.inputFiles:
		logger.debug("Working on file: %s", inputFile)
		if not os.path.isfile(inputFile):
			logger.error("%s does not exist, is not a proper file, or is a directory. Skipping it.", inputFile)
		else:
			if not os.access(inputFile, os.R_OK):
				logger.error("%s cannot be read. No read permissions. Skipping it.", inputFile)
			else:
				convertFile(inputFile, fileMap)
	logger.debug('time leaving doWork: %s', datetime.datetime.now())

# root

logging.basicConfig(stream=sys.stderr, level=basics.LOGGINGLEVEL)
logger = logging.getLogger('')

app = QtGui.QApplication(sys.argv)

settings = Settings() # initialize settings
# parse command line
parseArgs(sys.argv[1:], settings)

try:
	trezorChooser = TrezorChooser()
	trezor = trezorChooser.getDevice()
except (ConnectionError, RuntimeError), e:
	if settings.TArg:
		logger.critical("Connection to Trezor failed: %s", e.message)
	else:
		msgBox = QtGui.QMessageBox(QtGui.QMessageBox.Critical, "Trezor error", "Error: Connection to Trezor failed: " + e.message)
		msgBox.exec_()
	sys.exit(1)

if trezor is None:
	if settings.TArg:
		logger.critical("No available Trezor found, quitting.")
	else:
		msgBox = QtGui.QMessageBox(QtGui.QMessageBox.Critical, "Trezor error", "No available Trezor found, quitting.")
		msgBox.exec_()
	sys.exit(1)

trezor.clear_session()
logger.info("Trezor label: %s", trezor.features.label)


# if everything is specified in the command line then do not call the GUI
if ((settings.PArg is None) or (len(settings.inputFiles) <= 0)) and (not settings.TArg):
	# something was not specified, so we call the GUI
	showGui(trezor, settings)
else:
	logger.info("Everything was specified or --terminal was set, hence the GUI will not be called.")
if settings.PArg is None:
	settings.PArg = ""

try:
	fileMap = file_map.FileMap(trezor,logger)
	doWork(trezor, settings, fileMap)
except PinException:
	msgBox = QtGui.QMessageBox(text="Invalid PIN")
	msgBox.exec_()
	sys.exit(8)
except CallException:
	#button cancel on Trezor, so exit
	sys.exit(6)
except Exception, e:
	if settings.TArg:
		logger.critical(e.message)
	else:
		msgBox = QtGui.QMessageBox(QtGui.QMessageBox.Critical, "Work failed", "Error: " + e.message)
		msgBox.exec_()
	traceback.print_exc()
	sys.exit(5)

sys.exit(0)
