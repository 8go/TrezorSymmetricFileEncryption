from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import sys
import logging
import getopt

from PyQt5.QtWidgets import QMessageBox
from PyQt5.QtCore import QT_VERSION_STR
from PyQt5.Qt import PYQT_VERSION_STR

import basics
import encoding
from utils import BaseSettings, BaseArgs

"""
This is code that should be adapted to your applications.
This code implements Settings and Argument parsing.

Classes BaseSettings and BaseArgs from utils.py
should be subclassed her as Settings and Args.

Code should work on both Python 2.7 as well as 3.4.
Requires PyQt5.
(Old version supported PyQt4.)
"""


class Settings(BaseSettings):
	"""
	Placeholder for settings
	Settings such as command line options, GUI selected values,
	user input, etc.
	"""

	def __init__(self, logger=None, mlogger=None):
		"""
		@param logger: holds logger for where to log info/warnings/errors
			If None, a default logger will be created.
		@type logger: L{logging.Logger}
		@param mlogger: holds mlogger for where to log info/warnings/errors
			If None, a default mlogger will be created.
		@type mlogger: L{utils.MLogger}
		"""
		super(Settings, self).__init__(logger, mlogger)
		self.TArg = False
		self.EArg = False
		self.OArg = False
		self.DArg = False
		self.MArg = False
		self.NArg = False
		self.XArg = False  # -2, --twice
		self.PArg = None
		self.RArg = None  # -r read PIN
		self.AArg = None  # -R read passphrase
		self.SArg = False  # Safety check
		self.WArg = False  # Wipe plaintxt after encryption
		self.inputFiles = []  # list of input filenames

	def logSettings(self):
		self.logger.debug(self.__str__())

	def gui2Settings(self, dialog):
		"""
		This method should be implemented in the subclass.
		Copy the settings info from the dialog GUI to the Settings instance.
		"""
		self.DArg = dialog.dec()
		self.NArg = dialog.decFn()
		self.EArg = dialog.enc()
		self.MArg = dialog.encFn()
		self.OArg = dialog.encObf()
		self.XArg = dialog.encTwice()
		self.SArg = dialog.encSafe() or dialog.decSafe()
		self.WArg = dialog.encWipe() or dialog.decWipe()
		self.PArg = dialog.pw1()
		self.RArg = False
		self.AArg = False
		if self.PArg is None:
			self.PArg = ""
		# if passphrase has changed we must clear the session,
		# otherwise Trezor will used cached passphrase, i.e.
		# Trezor will not issue callback to ask for passphrase
		if (dialog.trezor.passphrase is None) or (dialog.trezor.passphrase != self.PArg.decode("utf-8")):
			self.mlogger.log("Passphrase has changed. If PIN is set it will "
				"have to be entered again.", logging.INFO,
				"Trezor IO")
			dialog.trezor.clear_session()
			dialog.trezor.prefillPassphrase(self.PArg)
			dialog.trezor.prefillReadpinfromstdin(False)
			dialog.trezor.prefillReadpassphrasefromstdin(False)
		self.inputFiles = dialog.selectedFiles()
		self.mlogger.log(self, logging.DEBUG, "Settings")

	def settings2Gui(self, dialog):
		"""
		This method should be implemented in the subclass.
		Copy the settings info from the Settings instance to the dialog GUI.
		"""
		dialog.setVersion(basics.VERSION_STR)
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
		dialog.setDecSafe(self.SArg and self.DArg)
		dialog.setEncWipe(self.WArg and self.EArg)
		dialog.setPw1(self.PArg)
		dialog.setPw2(self.PArg)
		if self.RArg:
			self.RArg = False
			self.mlogger.log("In GUI mode `-r` option will be ignored.",
				logging.INFO, "Arguments")
		if self.AArg:
			self.AArg = False
			self.mlogger.log("In GUI mode `-R` option will be ignored.",
				logging.INFO, "Arguments")
		dialog.trezor.prefillReadpinfromstdin(False)
		dialog.trezor.prefillReadpassphrasefromstdin(False)
		self.mlogger.log(self, logging.DEBUG, "Settings")

	def __str__(self):
		return(super(Settings, self).__str__() + "\n" +
			"settings.TArg = %s\n" % self.TArg +
			"settings.EArg = %s\n" % self.EArg +
			"settings.OArg = %s\n" % self.OArg +
			"settings.DArg = %s\n" % self.DArg +
			"settings.MArg = %s\n" % self.MArg +
			"settings.NArg = %s\n" % self.NArg +
			"settings.XArg = %s\n" % self.XArg +
			"settings.PArg = %s\n" % u"***" +  # do not log passphrase
			"settings.RArg = %s\n" % self.RArg +
			"settings.AArg = %s\n" % self.AArg +
			"settings.SArg = %s\n" % self.SArg +
			"settings.WArg = %s\n" % self.WArg +
			"settings.inputFiles = %s" % self.inputFiles)


class Args(BaseArgs):
	"""
	CLI Argument handling
	"""

	def __init__(self, settings, logger=None):
		"""
		Get all necessary parameters upfront, so the user
		does not have to provide them later on each call.

		@param settings: place to store settings
		@type settings: L{Settings}
		@param logger: holds logger for where to log info/warnings/errors
			if no logger is given it uses the default logger of settings.
			So, usually this would be None.
		@type logger: L{logging.Logger}
		"""
		super(Args, self).__init__(settings, logger)

	def printVersion(self):
		super(Args, self).printVersion()

	def printUsage(self):
		print("""TrezorSymmetricFileEncryption.py [-v] [-h] [-l <level>] [-t]
				[-e | -o | -d | -m | -n]
				[-2] [-s] [-w] [-p <passphrase>] [-r] [-R] <files>
		-v, --version
				print the version number
		-h, --help
				print short help text
		-l, --logging
				set logging level, integer from 1 to 5, 1=full logging, 5=no logging
		-t, --terminal
				run in the terminal, except for a possible PIN query
				and a Passphrase query this avoids the GUI
		-e, --encrypt
				encrypt file and keep output filename as plaintext
				(appends .tsfe suffix to input file)
		-o, --obfuscatedencrypt
				encrypt file and obfuscate output file name
		-d, --decrypt
				decrypt file
		-m, --encnameonly
				just encrypt the plaintext filename, show what the obfuscated
				filename would be; does not encrypt the file itself;
				incompaible with `-d` and `-n`
		-n, --decnameonly
				just decrypt the obfuscated filename;
				does not decrypt the file itself;
				incompaible with `-o`, `-e`, and `-m`
		-2, --twice
				paranoid mode; encrypt file a second time on the Trezor chip itself;
				only relevant for `-e` and `-o`; ignored in all other cases.
				Consider filesize: The Trezor chip is slow. 1M takes roughly 75 seconds.
		-p, --passphrase
				master passphrase used for Trezor.
				It is recommended that you do not use this command line option
				but rather give the passphrase through a small window interaction.
		-r, --readpinfromstdin
				read the PIN, if needed, from the standard input, i.e. terminal,
				when in terminal mode `-t`. By default, even with `-t` set
				it is read via a GUI window.
		-R, --readpassphrasefromstdin
				read the passphrase, when needed, from the standard input,
				when in terminal mode `-t`. By default, even with `-t` set
				it is read via a GUI window.
		-s, --safety
				doublechecks the encryption process by decrypting the just
				encrypted file immediately and comparing it to original file;
				doublechecks the decryption process by encrypting the just
				decrypted file immediately and comparing it to original file;
				Ignored for `-m` and `-n`.
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
		""")

	def parseArgs(self, argv, settings=None, logger=None):
		"""
		Parse the command line arguments and store the results in `settings`.
		Report errors to `logger`.

		@param settings: place to store settings;
			if None the default settings from the Args class will be used.
			So, usually this argument would be None.
		@type settings: L{Settings}
		@param logger: holds logger for where to log info/warnings/errors
			if None the default logger from the Args class will be used.
			So, usually this argument would be None.
		@type logger: L{logging.Logger}
		"""
		# do not call super class parseArgs as partial parsing does not work
		# superclass parseArgs is only useful if there are just -v -h -l [level]
		# get defaults
		if logger is None:
			logger = self.logger
		if settings is None:
			settings = self.settings
		try:
			opts, args = getopt.getopt(argv, "vhl:tmn2swdeop:rR",
				["version", "help", "logging=", "terminal", "encnameonly", "decnameonly",
				"twice", "safety", "decrypt", "encrypt", "obfuscatedencrypt",
				"passphrase=", "readpinfromstdin", "readpassphrasefromstdin"])
		except getopt.GetoptError as e:
			logger.critical(u'Wrong arguments. Error: %s.', e)
			try:
				msgBox = QMessageBox(QMessageBox.Critical, u"Wrong arguments",
					"Error: %s" % e)
				msgBox.exec_()
			except Exception:
				pass
			sys.exit(2)
		loglevelused = False
		for opt, arg in opts:
			if opt in ("-h", "--help"):
				self.printUsage()
				sys.exit()
			elif opt in ("-v", "--version"):
				self.printVersion()
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
			elif opt in ("-r", "--readpinfromstdin"):
				settings.RArg = True
			elif opt in ("-R", "--readpassphrasefromstdin"):
				settings.AArg = True

		if loglevelused:
			try:
				loglevel = int(loglevelarg)
			except Exception as e:
				self.settings.mlogger.log(u"Logging level not specified correctly. "
					"Must be integer between 1 and 5. (%s)" % loglevelarg, logging.CRITICAL,
					"Wrong arguments", settings.TArg, logger)
				sys.exit(18)
			if loglevel > 5 or loglevel < 1:
				self.settings.mlogger.log(u"Logging level not specified correctly. "
					"Must be integer between 1 and 5. (%s)" % loglevelarg, logging.CRITICAL,
					"Wrong arguments", settings.TArg, logger)
				sys.exit(19)
			settings.LArg = loglevel * 10  # https://docs.python.org/2/library/logging.html#levels
		logger.setLevel(settings.LArg)

		for arg in args:
			# convert all input as possible to unicode UTF-8 NFC
			settings.inputFiles.append(encoding.normalize_nfc(arg))
		if (settings.DArg and settings.EArg) or (settings.DArg and settings.OArg):
			self.mlogger.log("You cannot specify both decrypt and encrypt. "
				"It is one or the other. Either -d or -e or -o.", logging.CRITICAL,
				"Wrong arguments", True, logger)
			sys.exit(2)
		if (settings.MArg and settings.DArg) or (settings.MArg and settings.NArg):
			self.mlogger.log("You cannot specify both \"encrypt filename\" and "
				"\"decrypt file(name)\". It is one or the other. "
				"Don't use -m when using -d or -n (and vice versa).", logging.CRITICAL,
				"Wrong arguments", True, logger)
			sys.exit(2)
		if (settings.NArg and settings.EArg) or (settings.NArg and settings.OArg) or (settings.NArg and settings.MArg):
			self.mlogger.log("You cannot specify both \"decrypt filename\" and "
				"\"encrypt file(name)\". It is one or the other. Don't use "
				"-n when using -e, -o, or -m (and vice versa).", logging.CRITICAL,
				"Wrong arguments", True, logger)
			sys.exit(2)
		if settings.OArg:
			settings.EArg = True  # treat O like an extra flag, used in addition
		if settings.MArg:
			settings.EArg = False
			settings.OArg = False
		if settings.NArg:
			settings.DArg = False
		if (settings.MArg and settings.DArg):
			self.mlogger.log("You cannot specify -d and -m at the same time.", logging.CRITICAL,
				"Wrong arguments", True, logger)
			sys.exit(2)
		if (settings.NArg and settings.EArg) or (settings.NArg and settings.OArg):
			self.mlogger.log("You cannot specify -e or -o at the same time as -n.", logging.CRITICAL,
				"Wrong arguments", True, logger)
			sys.exit(2)
		if (settings.MArg and settings.OArg) or (settings.MArg and settings.XArg) or \
			(settings.MArg and settings.SArg) or (settings.MArg and settings.WArg):
			self.mlogger.log("You cannot specify -o, -2, -s or -w with -m", logging.CRITICAL,
				"Wrong arguments", True, logger)
			sys.exit(2)
		if (settings.NArg and settings.OArg) or (settings.NArg and settings.XArg) or \
			(settings.NArg and settings.SArg) or (settings.NArg and settings.WArg):
			self.mlogger.log("You cannot specify -o, -2, -s or -w with -n", logging.CRITICAL,
				"Wrong arguments", True, logger)
			sys.exit(2)
		if (settings.DArg and settings.OArg) or (settings.DArg and settings.XArg):
			self.mlogger.log("You cannot specify -o or -2 with -d", logging.CRITICAL,
				"Wrong arguments", True, logger)
			sys.exit(2)

		settings.mlogger.setTerminalMode(settings.TArg)
		self.settings.mlogger.log(u"%s Version: %s (%s)" %
			(basics.NAME, basics.VERSION_STR, basics.VERSION_DATE_STR),
			logging.INFO, "Version", True, logger)
		self.settings.mlogger.log(u"Python: %s" % sys.version.replace(" \n", "; "),
			logging.INFO, "Version", True, logger)
		self.settings.mlogger.log(u"Qt Version: %s" % QT_VERSION_STR,
			logging.INFO, "Version", True, logger)
		self.settings.mlogger.log(u"PyQt Version: %s" % PYQT_VERSION_STR,
			logging.INFO, "Version", True, logger)
		self.settings.mlogger.log(u'Logging level set to %s (%d).' %
			(logging.getLevelName(settings.LArg), settings.LArg),
			logging.INFO, "Logging", True, logger)
		self.settings.mlogger.log(self.settings,
			logging.DEBUG, "Settings", True, logger)
