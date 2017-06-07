# -*- coding: utf-8 -*-
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
from encoding import normalize_nfc

"""
This is generic code that should work untouched accross all applications.
This code implements Logging for both Terminal and GUI mode.
It implements Settings and Argument parsing.

Code should work on both Python 2.7 as well as 3.4.
Requires PyQt5.
(Old version supported PyQt4.)
"""


def input23(prompt=u''):  # Py2-vs-Py3:
	"""
	Utility function to bridge Py2 and Py3 incompatibilities.
	Maps Py2 raw_input() to input() for Py2.
	Py2: raw_input()
	Py3: input()
	"""
	if sys.version_info[0] < 3:  # Py2-vs-Py3:
		return normalize_nfc(raw_input(prompt))
	else:
		return normalize_nfc(input(prompt))


class MLogger(object):
	"""
	class for logging that covers, print, logger, and writing to GUI QTextBrowser widget.
	Its is called *M*Logger because it can log to *M*ultiple streams
	such as stdout, QTextBrowser, msgBox, ...
	Alternatively, he MLogger could have been implemented according to this
	strategy: https://stackoverflow.com/questions/24469662/how-to-redirect-logger-output-into-pyqt-text-widget
	"""

	def __init__(self, terminalMode=None, logger=None, qtextbrowser=None):
		"""
		Get as many necessary parameters upfront as possible, so the user
		does not have to provide them later on each call.

		@param terminalMode: log only to terminal?
		@type terminalMode: C{bool}
		@param logger: holds logger for where to log info/warnings/errors
		@type logger: L{logging.Logger}
		@param qtextbrowser: holds GUI widget for where to log info/warnings/errors
		@type qtextbrowser: L{PyQt5.QtWidgets.QTextBrowser}
		"""
		self.terminalMode = terminalMode
		self.logger = logger
		self.qtextbrowser = qtextbrowser
		# qtextbrowser text will be created by assembling:
		# qtextheader + qtextContent + qtextTrailer
		self.qtextheader = u''
		self.qtextcontent = u''
		self.qtexttrailer = u''

	def setTerminalMode(self, terminalMode):
		self.terminalMode = terminalMode

	def setLogger(self, logger):
		self.logger = logger

	def setQtextbrowser(self, qtextbrowser):
		"""
		@param qtextbrowser: holds GUI widget for where to log info/warnings/errors
		@type qtextbrowser: L{PyQt5.QtWidgets.QTextBrowser}
		"""
		self.qtextbrowser = qtextbrowser

	def setQtextheader(self, str):
		"""
		@param str: string to report/log
		@type str: C{string}
		"""
		self.qtextheader = str

	def setQtextcontent(self, str):
		"""
		@param str: string to report/log
		@type str: C{string}
		"""
		self.qtextcontent = str

	def appendQtextcontent(self, str):
		"""
		@param str: string to report/log
		@type str: C{string}
		"""
		self.qtextcontent += str

	def setQtexttrailer(self, str):
		"""
		@param str: string to report/log
		@type str: C{string}
		"""
		self.qtexttrailer = str

	def qtext(self):
		return self.qtextheader + self.qtextcontent + self.qtexttrailer

	def moveCursorToBottomQtext(self):
		# move the cursor to the end of the text, scroll to the bottom
		cursor = self.qtextbrowser.textCursor()
		cursor.setPosition(len(self.qtextbrowser.toPlainText()))
		self.qtextbrowser.ensureCursorVisible()
		self.qtextbrowser.setTextCursor(cursor)

	def publishQtext(self):
		self.qtextbrowser.setHtml(self.qtext())
		self.moveCursorToBottomQtext()

	def log(self, str, level, title, terminalMode=None, logger=None, qtextbrowser=None):
		"""
		Displays string `str` depending on scenario:
		a) in terminal mode: thru logger (except if loglevel == NOTSET)
		b) in GUI mode and GUI window open: (qtextbrowser!=None) in qtextbrowser of GUI window
		c) in GUI mode but window still/already closed: (qtextbrowser==None) thru QMessageBox()

		If terminalMode=None, logger=None, qtextbrowser=None, then the
		corresponding value from self is used. So, None means this
		value should default to the preset value of the class Log.

		@param str: string to report/log
		@type str: C{string}
		@param level: log level from DEBUG to CRITICAL from L{logging}
		@type level: C{int}
		@param title: window title text (only used if there is a window)
		@type title: C{string}

		@param terminalMode: log only to terminal?
		@type terminalMode: C{bool}
		@param logger: holds logger for where to log info/warnings/errors
		@type logger: L{logging.Logger}
		@param qtextbrowser: holds GUI widget for where to log info/warnings/errors
		@type qtextbrowser: L{PyQt5.QtWidgets.QTextBrowser}
		"""
		# get defaults
		if terminalMode is None:
			terminalMode = self.terminalMode
		if logger is None:
			logger = self.logger
		if qtextbrowser is None:
			qtextbrowser = self.qtextbrowser
		# initialize
		if logger is None:
			logging.basicConfig(stream=sys.stderr, level=basics.DEFAULT_LOG_LEVEL)
			logger = logging.getLogger(basics.LOGGER_ACRONYM)
		if qtextbrowser is None:
			guiExists = False
		else:
			guiExists = True
		if guiExists:
			if terminalMode is None:
				terminalMode = False
		else:
			if terminalMode is None:
				terminalMode = True
		if level == logging.NOTSET:
			if terminalMode:
				print(str)  # stdout
			elif guiExists:
				print(str)  # stdout
				self.appendQtextcontent(u"<br>%s" % (str))
			else:
				print(str)  # stdout
				try:
					msgBox = QMessageBox(QMessageBox.Information,
						title, u"%s" % (str))
					msgBox.exec_()
				except Exception:
					pass
		elif level == logging.DEBUG:
			if terminalMode:
				logger.debug(str)
			elif guiExists:
				logger.debug(str)
				if logger.getEffectiveLevel() <= level:
					self.appendQtextcontent(u"<br>Debug: %s" % str)
			else:
				# don't spam the user with too many pop-ups
				# For debug, instead of a pop-up we write to stdout
				logger.debug(str)
		elif level == logging.INFO:
			if terminalMode:
				logger.info(str)
			elif guiExists:
				logger.info(str)
				if logger.getEffectiveLevel() <= level:
					self.appendQtextcontent(u"<br>Info: %s" % (str))
			else:
				logger.info(str)
				if logger.getEffectiveLevel() <= level:
					try:
						msgBox = QMessageBox(QMessageBox.Information,
							title, u"Info: %s" % (str))
						msgBox.exec_()
					except Exception:
						pass
		elif level == logging.WARNING:
			if terminalMode:
				logger.warning(str)
			elif guiExists:
				logger.warning(str)
				if logger.getEffectiveLevel() <= level:
					self.appendQtextcontent(u"<br>Warning: %s" % (str))
			else:
				logger.warning(str)
				if logger.getEffectiveLevel() <= level:
					try:
						msgBox = QMessageBox(QMessageBox.Warning,
							title, u"Warning: %s" % (str))
						msgBox.exec_()
					except Exception:
						pass
		elif level == logging.ERROR:
			if terminalMode:
				logger.error(str)
			elif guiExists:
				logger.error(str)
				if logger.getEffectiveLevel() <= level:
					self.appendQtextcontent(u"<br>Error: %s" % (str))
			else:
				logger.error(str)
				if logger.getEffectiveLevel() <= level:
					try:
						msgBox = QMessageBox(QMessageBox.Critical,
							title, u"Error: %s" % (str))
						msgBox.exec_()
					except Exception:
						pass
		elif level == logging.CRITICAL:
			if terminalMode:
				logger.critical(str)
			elif guiExists:
				logger.critical(str)
				if logger.getEffectiveLevel() <= level:
					self.appendQtextcontent(u"<br>Critical: %s" % (str))
			else:
				logger.critical(str)
				if logger.getEffectiveLevel() <= level:
					try:
						msgBox = QMessageBox(QMessageBox.Critical,
							title, u"Critical: %s" % (str))
						msgBox.exec_()
					except Exception:
						pass
		if qtextbrowser is not None:
			# flush changes to GUI
			self.publishQtext()


class BaseSettings(object):
	"""
	Placeholder for settings
	Settings such as command line options, GUI selected values,
	user input, etc.
	This class is supposed to be subclassed, e.g. as Settings
	to adapt to the specifics of the application.
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
		self.VArg = False
		self.HArg = False
		self.LArg = basics.DEFAULT_LOG_LEVEL

		if logger is None:
			"""
			If "import sys" is not repeated here then
			logger will fail with error
			UnicodeEncodeError: 'latin-1' codec can't encode character '\u1ebd' in position 1: ordinal not in range(256)
			when foreign strings like "ñẽë儿ë" are used in the command line.
			"""
			import sys
			logging.basicConfig(stream=sys.stderr, level=basics.DEFAULT_LOG_LEVEL)
			self.logger = logging.getLogger(basics.LOGGER_ACRONYM)
		else:
			self.logger = logger

		if mlogger is None:
			self.mlogger = MLogger(terminalMode=None, logger=self.logger, qtextbrowser=None)
		else:
			self.mlogger = mlogger

	def logSettings(self):
		self.logger.debug(self.__str__())

	def gui2Settings(self, dialog):
		"""
		This method should be implemented in the subclass.
		Copy the settings info from the dialog GUI to the Settings instance.
		"""
		pass

	def settings2Gui(self, dialog):
		"""
		This method should be implemented in the subclass.
		Copy the settings info from the Settings instance to the dialog GUI.
		"""
		pass

	def __str__(self):
		return("settings.VArg = %s\n" % self.VArg +
			"settings.HArg = %s\n" % self.HArg +
			"settings.LArg = %s" % self.LArg)


class BaseArgs(object):
	"""
	CLI Argument handling
	This class is supposed to be subclassed, e.g. as Args
	to adapt to the specifics of the application.
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
		self.settings = settings
		if logger is None:
			self.logger = settings.logger
		else:
			self.logger = logger

	def printVersion(self):
		print(u"%s Version: %s (%s)" % (basics.NAME, basics.VERSION_STR, basics.VERSION_DATE_STR))
		print(u"Python: %s" % sys.version.replace(" \n", "; "))
		print(u"Qt Version: %s" % QT_VERSION_STR)
		print(u"PyQt Version: %s" % PYQT_VERSION_STR)

	def printUsage(self):
		"""
		This method should be implemented in the subclass.
		"""
		print(basics.NAME + '''.py [-h] [-v] [-l <loglevel>]
		-v, --version
				Print the version number
		-h, --help
			Print help text
		-l, --logging
			Set logging level, integer from 1 to 5, 1=full logging, 5=no logging
		''')

	def parseArgs(self, argv, settings=None, logger=None):
		"""
		Parse the command line arguments and store the results in `settings`.
		Report errors to `logger`.

		This method should be implemented in the subclass.
		Calling this method is only useful when the application has exactly
		the 3 arguments -h -v -l [level]

		@param settings: place to store settings;
			if None the default settings from the Args class will be used.
			So, usually this argument would be None.
		@type settings: L{Settings}
		@param logger: holds logger for where to log info/warnings/errors
			if None the default logger from the Args class will be used.
			So, usually this argument would be None.
		@type logger: L{logging.Logger}
		"""
		# get defaults
		if logger is None:
			logger = self.logger
		if settings is None:
			settings = self.settings
		try:
			opts, args = getopt.getopt(argv, "vhl:",
				["version", "help", "logging="])
		except getopt.GetoptError as e:
			msgBox = QMessageBox(QMessageBox.Critical, u"Wrong arguments",
				u"Error: %s" % e)
			msgBox.exec_()
			logger.critical(u'Wrong arguments. Error: %s.', e)
			sys.exit(2)
		loglevelused = False
		for opt, arg in opts:
			arg = normalize_nfc(arg)
			if opt in ("-h", "--help"):
				self.printUsage()
				sys.exit()
			elif opt in ("-v", "--version"):
				self.printVersion()
				sys.exit()
			elif opt in ("-l", "--logging"):
				loglevelarg = arg
				loglevelused = True

		if loglevelused:
			try:
				loglevel = int(loglevelarg)
			except Exception:
				self.settings.mlogger.log(u"Logging level not specified correctly. "
					"Must be integer between 1 and 5. (%s)" % loglevelarg, logging.CRITICAL,
					"Wrong arguments", True, logger)
				sys.exit(18)
			if loglevel > 5 or loglevel < 1:
				self.settings.mlogger.log(u"Logging level not specified correctly. "
					"Must be integer between 1 and 5. (%s)" % loglevelarg, logging.CRITICAL,
					"Wrong arguments", True, logger)
				sys.exit(19)
			settings.LArg = loglevel * 10  # https://docs.python.org/2/library/logging.html#levels
		logger.setLevel(settings.LArg)

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
		self.settings.mlogger.log(settings,
			logging.DEBUG, "Settings", True, logger)
