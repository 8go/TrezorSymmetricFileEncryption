from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import os
import os.path
import logging
import sys

from PyQt5.QtWidgets import QApplication, QDialog, QDialogButtonBox, QShortcut
from PyQt5.QtWidgets import QMessageBox, QFileDialog
from PyQt5.QtGui import QPixmap, QKeySequence
from PyQt5.QtCore import QT_VERSION_STR, QDir
from PyQt5.Qt import PYQT_VERSION_STR

from ui_dialog import Ui_Dialog

import basics
import encoding
from processing import processAll

"""
This code should cover the GUI of the business logic of the application.

Code should work on both Python 2.7 as well as 3.4.
Requires PyQt5.
(Old version supported PyQt4.)
"""


class Dialog(QDialog, Ui_Dialog):

	DESCRHEADER = """<!DOCTYPE html><html><head>
		<body style="font-size:11pt; font-weight:400; font-style:normal;">
		<b>Welcome to """ + basics.NAME + """</b>, version """ + basics.VERSION_STR + """ from
		""" + basics.VERSION_DATE_STR + """<br>
		En/decrypting once is fast.
		En/decrypting twice is slow on large files.
		<br>If you lose your master passphrase you will not be able to
		decrypt your file(s). You may leave the master passphrase empty.<br>
		"""
	DESCRTRAILER = "</p></body></html>"

	def __init__(self, trezor, settings):
		super(Dialog, self).__init__()

		# Set up the user interface from Designer.
		self.setupUi(self)

		self.trezor = trezor
		self.settings = settings
		self.fileMap = None

		self.radioButtonEncFile.toggled.connect(self.validateEncFile)
		self.radioButtonEncFilename.toggled.connect(self.validateEncFilename)
		self.radioButtonDecFile.toggled.connect(self.validateDecFile)
		self.radioButtonDecFilename.toggled.connect(self.validateDecFilename)
		self.checkBoxEncO.toggled.connect(self.validateEncO)
		self.checkBoxEnc2.toggled.connect(self.validateEnc2)
		self.checkBoxEncS.toggled.connect(self.validateEncS)
		self.checkBoxEncW.toggled.connect(self.validateEncW)
		self.checkBoxDecS.toggled.connect(self.validateDecS)
		self.checkBoxDecW.toggled.connect(self.validateDecW)

		self.checkBoxEncO.setEnabled(False)
		self.checkBoxEnc2.setEnabled(False)
		self.checkBoxEncS.setEnabled(False)
		self.checkBoxEncW.setEnabled(False)
		self.checkBoxDecW.setEnabled(False)
		self.checkBoxDecS.setEnabled(False)

		self.masterEdit1.textChanged.connect(self.validate)
		self.masterEdit2.textChanged.connect(self.validate)
		self.selectedFileEdit.textChanged.connect(self.validate)
		self.selectedFileButton.clicked.connect(self.selectFile)
		self.validate()
		self.version = u''
		self.fileNames = []
		self.description1 = self.DESCRHEADER
		self.description2 = u''
		self.description3 = self.DESCRTRAILER

		# Apply is not automatically set up, only OK is automatically set up
		button = self.buttonBox.button(QDialogButtonBox.Apply)  # QtGui.QDialogButtonBox.Ok
		button.clicked.connect(self.accept)
		# Abort is automatically set up as Reject, like Cancel

		# self.buttonBox.clicked.connect(self.handleButtonClick)  # connects ALL buttons
		# Created the action in GUI with designer-qt4
		self.actionApply.triggered.connect(self.accept)  # Save
		self.actionDone.triggered.connect(self.reject)  # Quit
		QShortcut(QKeySequence(u"Ctrl+Q"), self, self.reject)  # Quit
		QShortcut(QKeySequence(u"Ctrl+S"), self, self.accept)  # Save
		QShortcut(QKeySequence(u"Ctrl+A"), self, self.accept)  # Apply
		QShortcut(QKeySequence(u"Ctrl+C"), self, self.copy2Clipboard)
		QShortcut(QKeySequence(u"Ctrl+V"), self, self.printAbout)  # Version/About
		QShortcut(QKeySequence(u"Ctrl+E"), self, self.setEnc)  # Enc
		QShortcut(QKeySequence(u"Ctrl+D"), self, self.setDec)  #
		QShortcut(QKeySequence(u"Ctrl+O"), self, self.setEncObf)  #
		QShortcut(QKeySequence(u"Ctrl+2"), self, self.setEncTwice)  #
		QShortcut(QKeySequence(u"Ctrl+T"), self, self.setEncDecSafe)  #
		QShortcut(QKeySequence(u"Ctrl+W"), self, self.setEncDecWipe)  #
		QShortcut(QKeySequence(u"Ctrl+M"), self, self.setEncFn)  #
		QShortcut(QKeySequence(u"Ctrl+N"), self, self.setDecFn)  #

		self.clipboard = QApplication.clipboard()
		self.textBrowser.selectionChanged.connect(self.selectionChanged)

	def descrHeader(self):
		return self.DESCRHEADER

	def descrContent(self):
		return self.description2

	def descrTrailer(self):
		return self.DESCRTRAILER

	def printAbout(self):
		"""
		Show window with about and version information.
		"""
		msgBox = QMessageBox(QMessageBox.Information, "About",
			"About <b>" + basics.NAME + "</b>: <br><br>" + basics.NAME + " " +
			"is a file encryption and decryption tool using a Trezor hardware "
			"device for safety and security. Symmetric AES cryptography is used "
			"at its core. <br><br>" +
			"<b>" + basics.NAME + " Version: </b>" + basics.VERSION_STR +
			" from " + basics.VERSION_DATE_STR +
			"<br><br><b>Python Version: </b>" + sys.version.replace(" \n", "; ") +
			"<br><br><b>Qt Version: </b>" + QT_VERSION_STR +
			"<br><br><b>PyQt Version: </b>" + PYQT_VERSION_STR)
		msgBox.setIconPixmap(QPixmap(basics.LOGO_IMAGE))
		msgBox.exec_()

	def validateDecFile(self):
		if self.checkBoxEncO.isChecked():
			self.checkBoxEncO.setChecked(False)
		if self.checkBoxEnc2.isChecked():
			self.checkBoxEnc2.setChecked(False)
		if self.checkBoxEncS.isChecked():
			self.checkBoxEncS.setChecked(False)
		if self.checkBoxEncW.isChecked():
			self.checkBoxEncW.setChecked(False)
		self.checkBoxEncO.setEnabled(False)
		self.checkBoxEnc2.setEnabled(False)
		self.checkBoxEncS.setEnabled(False)
		self.checkBoxEncW.setEnabled(False)
		self.checkBoxDecW.setEnabled(True)
		self.checkBoxDecS.setEnabled(True)
		self.validate()

	def validateDecFilename(self):
		if self.checkBoxEncO.isChecked():
			self.checkBoxEncO.setChecked(False)
		if self.checkBoxEnc2.isChecked():
			self.checkBoxEnc2.setChecked(False)
		if self.checkBoxEncS.isChecked():
			self.checkBoxEncS.setChecked(False)
		if self.checkBoxEncW.isChecked():
			self.checkBoxEncW.setChecked(False)
		if self.checkBoxDecS.isChecked():
			self.checkBoxDecS.setChecked(False)
		if self.checkBoxDecW.isChecked():
			self.checkBoxDecW.setChecked(False)
		self.checkBoxEncO.setEnabled(False)
		self.checkBoxEnc2.setEnabled(False)
		self.checkBoxEncS.setEnabled(False)
		self.checkBoxEncW.setEnabled(False)
		self.checkBoxDecS.setEnabled(False)
		self.checkBoxDecW.setEnabled(False)
		self.validate()

	def validateEncFile(self):
		if self.checkBoxDecS.isChecked():
			self.checkBoxDecS.setChecked(False)
		if self.checkBoxDecW.isChecked():
			self.checkBoxDecW.setChecked(False)
		self.checkBoxEncO.setEnabled(True)
		self.checkBoxEnc2.setEnabled(True)
		self.checkBoxEncS.setEnabled(True)
		self.checkBoxEncW.setEnabled(True)
		self.checkBoxDecS.setEnabled(False)
		self.checkBoxDecW.setEnabled(False)
		self.validate()

	def validateEncFilename(self):
		if self.checkBoxEncO.isChecked():
			self.checkBoxEncO.setChecked(False)
		if self.checkBoxEnc2.isChecked():
			self.checkBoxEnc2.setChecked(False)
		if self.checkBoxEncS.isChecked():
			self.checkBoxEncS.setChecked(False)
		if self.checkBoxEncW.isChecked():
			self.checkBoxEncW.setChecked(False)
		if self.checkBoxDecS.isChecked():
			self.checkBoxDecS.setChecked(False)
		if self.checkBoxDecW.isChecked():
			self.checkBoxDecW.setChecked(False)
		self.checkBoxEncO.setEnabled(False)
		self.checkBoxEnc2.setEnabled(False)
		self.checkBoxEncS.setEnabled(False)
		self.checkBoxEncW.setEnabled(False)
		self.checkBoxDecS.setEnabled(False)
		self.checkBoxDecW.setEnabled(False)
		self.validate()

	def validateEncO(self):
		if self.checkBoxEncO.isChecked():
				self.settings.mlogger.log("You have selected the option `--obfuscate`. "
				"After encrypting the file(s) the encrypted file(s) will be "
				"renamed to encrypted, strange looking names. This hides the meta-data,"
				"i.e. the filename.", logging.INFO, "Arguments")

	def validateEnc2(self):
		if self.checkBoxEnc2.isChecked():
				self.settings.mlogger.log("You have selected the option `--twice`. "
				"Files will be encrypted not on your computer but on the Trezor "
				"device itself. This is slow. It takes 75 seconds for 1M. "
				"In other words, 0.8M/min. "
				"Remove this option if the file is too big or "
				"you do not want to wait.", logging.INFO,
				"Dangerous arguments")

	def validateEncS(self):
		if self.checkBoxEncS.isChecked():
				self.settings.mlogger.log("You have selected the option `--safety`. "
				"After encrypting the file(s) the file(s) will immediately "
				"be decrypted and the output compared to the original file(s). "
				"This safety check definitely guarantees that all is well.", logging.INFO,
				"Arguments")

	def validateEncW(self):
		if self.checkBoxEncW.isChecked():
				self.settings.mlogger.log("You have selected the option `--wipe`. "
				"The original plaintext files will "
				"be shredded and permanently deleted after encryption. "
				"Remove this option if you are uncertain or don't understand.", logging.WARN,
				"Dangerous arguments")

	def validateDecS(self):
		if self.checkBoxEncS.isChecked():
				self.settings.mlogger.log("You have selected the option `--safety`. "
				"After decrypting the file(s) the file(s) will immediately "
				"be encrypted and the output compared to the original file(s). "
				"This safety check definitely guarantees that all is well.", logging.INFO,
				"Arguments")

	def validateDecW(self):
		if self.checkBoxDecW.isChecked():
				self.settings.mlogger.log("You have selected the option `--wipe`. "
				"The encrypted files will be shredded and permanently deleted after decryption. "
				"Remove this option if you are uncertain or don't understand.", logging.WARN,
				"Dangerous arguments")

	def selectionChanged(self):
		"""
		called whenever selected text in textarea is changed
		"""
		# self.textBrowser.copy()  # copy selected to clipboard
		# self.settings.mlogger.log("Copied text to clipboard: %s" % self.clipboard.text(),
		# 	logging.DEBUG, "Clipboard")
		pass

	def copy2Clipboard(self):
		self.textBrowser.copy()  # copy selected to clipboard
		# This is content from the Status textarea, so no secrets here, we can log it
		self.settings.mlogger.log("Copied text to clipboard: %s" % self.clipboard.text(),
			logging.DEBUG, "Clipboard")

	def setFileMap(self, fileMap):
		self.fileMap = fileMap

	def setVersion(self, version):
		self.version = version

	def setDescription(self, extradescription):
		self.textBrowser.setHtml(self.description1 + extradescription + self.description3)

	def appendDescription(self, extradescription):
		"""
		@param extradescription: text in HTML format, use </br> for linebreaks
		"""
		self.description2 += extradescription
		self.textBrowser.setHtml(self.description1 + self.description2 + self.description3)

	def encObf(self):
		"""
		Returns True if radio button for option "encrypt and obfuscate filename"
		is selected
		"""
		return self.checkBoxEncO.isChecked()

	def setEncObf(self, arg=True):
		self.checkBoxEncO.setChecked(arg)

	def encTwice(self):
		return self.checkBoxEnc2.isChecked()

	def setEncTwice(self, arg=True):
		self.checkBoxEnc2.setChecked(arg)

	def encSafe(self):
		return self.checkBoxEncS.isChecked()

	def setEncSafe(self, arg=True):
		self.checkBoxEncS.setChecked(arg)

	def decSafe(self):
		return self.checkBoxDecS.isChecked()

	def setDecSafe(self, arg=True):
		self.checkBoxDecS.setChecked(arg)

	def setEncDecSafe(self, arg=True):
		if self.enc():
			self.setEncSafe(arg)
		if self.dec():
			self.setDecSafe(arg)

	def encWipe(self):
		return self.checkBoxEncW.isChecked()

	def setEncWipe(self, arg=True):
		self.checkBoxEncW.setChecked(arg)

	def decWipe(self):
		return self.checkBoxDecW.isChecked()

	def setDecWipe(self, arg=True):
		self.checkBoxDecW.setChecked(arg)

	def setEncDecWipe(self, arg=True):
		if self.enc():
			self.setEncWipe(arg)
		if self.dec():
			self.setDecWipe(arg)

	def enc(self):
		"""
		Returns True if radio button for option "encrypt with plaintext filename"
		is selected
		"""
		return self.radioButtonEncFile.isChecked()

	def setEnc(self, arg=True):
		self.radioButtonEncFile.setChecked(arg)

	def encFn(self):
		"""
		Returns True if radio button for option "encrypt with plaintext filename"
		is selected
		"""
		return self.radioButtonEncFilename.isChecked()

	def setEncFn(self, arg=True):
		self.radioButtonEncFilename.setChecked(arg)

	def dec(self):
		"""
		Returns True if radio button for option "decrypt" is selected
		"""
		return self.radioButtonDecFile.isChecked()

	def setDec(self, arg=True):
		self.radioButtonDecFile.setChecked(arg)

	def decFn(self):
		"""
		Returns True if radio button for option "decrypt only filename" is
		selected
		"""
		return self.radioButtonDecFilename.isChecked()

	def setDecFn(self, arg=True):
		self.radioButtonDecFilename.setChecked(arg)

	def pw1(self):
		return encoding.normalize_nfc(self.masterEdit1.text())

	def setPw1(self, arg):
		self.masterEdit1.setText(encoding.normalize_nfc(arg))

	def pw2(self):
		return encoding.normalize_nfc(self.masterEdit2.text())

	def setPw2(self, arg):
		self.masterEdit2.setText(encoding.normalize_nfc(arg))

	def setSelectedFile(self, fileNames):
		"""
		Takes a py list as input and concatenates it and
		then places it into the single-line text field
		"""
		filenamesconcat = ""
		for file in fileNames:
			head, tail = os.path.split(file)
			filenamesconcat += '"' + tail + '"' + ' '
		self.selectedFileEdit.setText(encoding.normalize_nfc(filenamesconcat))

	def setSelectedFiles(self, fileNames):
		"""
		Takes a py list as input
		"""
		self.fileNames = fileNames

	def selectedFile(self):
		"""
		This returns a concatenated string of basenames.
		This is most likely not what you want.
		Most likely you want a nice list of full filenames with paths,
		so use selectedFiles()
		"""
		return self.selectedFileEdit.text()

	def selectedFiles(self):
		"""
		Returns a list of full filenames with paths
		"""
		return self.fileNames

	def selectFile(self):
		"""
		Show file dialog and return file(s) user has chosen.
		"""
		path = QDir.currentPath()
		dialog = QFileDialog(self, "Select file(s)",
			path, "(*)")
		dialog.setFileMode(QFileDialog.ExistingFiles)
		dialog.setAcceptMode(QFileDialog.AcceptOpen)

		res = dialog.exec_()
		if not res:
			return

		# in Qt4 this was QStringList, in Qt5 this is a regular list of unicode strings
		self.fileNames = dialog.selectedFiles()
		self.settings.mlogger.log("Selected files are: %s" % self.fileNames,
			logging.DEBUG, "GUI IO")
		self.setSelectedFile(self.fileNames)

	def validate(self):
		"""
		Enable OK/Apply buttons only if both master and backup are repeated
		without typo and some file is selected and
		exactly a single decrypt/encrypt option from the radio buttons is set.
		And only when Encrypt is selected.
		On decrypt passphrase does not need to be specified twice.
		"""
		if self.dec() or self.decFn():
			self.labelPw2.setText(u"Neither needed nor used to decrypt")
		else:
			self.labelPw2.setText(u"Repeat master passphrase for Trezor")

		same = self.pw1() == self.pw2()
		fileSelected = (self.selectedFileEdit.text() != u'')

		# QDialogButtonBox.Ok
		button = self.buttonBox.button(QDialogButtonBox.Apply)
		button.setEnabled(fileSelected and (same or self.dec() or self.decFn()))
		return fileSelected and (same or self.dec() or self.decFn())

	# def handleButtonClick(self, button):
		# sb = self.buttonBox.standardButton(button)
		# if sb == QDialogButtonBox.Apply:
		# 	processAll(self.fileMap, self.settings, self)
		# # elif sb == QDialogButtonBox.Reset:
		# #	self.settings.mlogger.log("Reset Clicked, quitting now...", logging.DEBUG,
		# #		"UI")

	def accept(self):
		"""
		Apply button was pressed
		"""
		if self.validate():
			self.settings.mlogger.log("Apply was called by user request. Start processing now.",
				logging.DEBUG, "GUI IO")
			processAll(self.fileMap, self.settings, self)  #
		else:
			self.settings.mlogger.log("Apply was called by user request. Apply is denied. "
				"User input is not valid for processing. Did you select a file?",
				logging.DEBUG, "GUI IO")

	# Don't set up a reject() method, it is automatically created.
	# If created here again it would overwrite the default one
	# def reject(self):
	# 	self.close()
