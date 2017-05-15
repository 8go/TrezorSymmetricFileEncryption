import os
import os.path
import base64
import hashlib
import logging

from PyQt4 import QtGui, QtCore
from PyQt4.QtGui import QPixmap

from ui_trezor_passphrase_dialog import Ui_TrezorPassphraseDialog
from ui_dialog import Ui_Dialog
from ui_enter_pin_dialog import Ui_EnterPinDialog
from ui_trezor_chooser_dialog import Ui_TrezorChooserDialog

from encoding import q2s, s2q
from processing import processAll, reportLogging

import basics

class TrezorPassphraseDialog(QtGui.QDialog, Ui_TrezorPassphraseDialog):

	def __init__(self):
		QtGui.QDialog.__init__(self)
		self.setupUi(self)

	def passphrase(self):
		return self.passphraseEdit.text()

class Dialog(QtGui.QDialog, Ui_Dialog):

	def __init__(self, trezor, settings, fileMap, logger):
		QtGui.QDialog.__init__(self)
		self.setupUi(self)

		self.trezor = trezor
		self.settings = settings
		self.fileMap = fileMap
		self.logger = logger

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
		self.version = ""
		self.fileNames = []
		self.description1 = """<!DOCTYPE html><html><head>
			<body style="font-size:11pt; font-weight:400; font-style:normal;">
			<b>Welcome to TrezorSymmetricFileEncryption</b><br>
			En/decrypting once is fast.
			En/decrypting twice is slow on large files.
			<br>If you lose your master passphrase you will not be able to
			decrypt your file(s). You may leave the master passphrase empty.<br>
			"""
		self.description2 = ""
		self.description3 = "</p></body></html>"

		# Apply is not automatically set up, only OK is automatically set up
		button = self.buttonBox.button(QtGui.QDialogButtonBox.Apply) # QtGui.QDialogButtonBox.Ok
		button.clicked.connect(self.accept)
		# Abort is automatically set up as Reject, like Cancel

		# self.buttonBox.clicked.connect(self.handleButtonClick) # connects ALL buttons
		# Created the action in GUI with designer-qt4
		self.actionApply.triggered.connect(self.accept) # Save
		self.actionDone.triggered.connect(self.reject) # Quit
		QtGui.QShortcut(QtGui.QKeySequence("Ctrl+Q"), self, self.reject) # Quit
		QtGui.QShortcut(QtGui.QKeySequence("Ctrl+S"), self, self.accept) # Save
		QtGui.QShortcut(QtGui.QKeySequence("Ctrl+A"), self, self.accept) # Apply
		QtGui.QShortcut(QtGui.QKeySequence("Ctrl+C"), self, self.copy2Clipboard)
		QtGui.QShortcut(QtGui.QKeySequence("Ctrl+V"), self, self.printAbout) # Version/About
		QtGui.QShortcut(QtGui.QKeySequence("Ctrl+E"), self, self.setEnc) # Enc
		QtGui.QShortcut(QtGui.QKeySequence("Ctrl+D"), self, self.setDec) #
		QtGui.QShortcut(QtGui.QKeySequence("Ctrl+O"), self, self.setEncObf) #
		QtGui.QShortcut(QtGui.QKeySequence("Ctrl+2"), self, self.setEncTwice) #
		QtGui.QShortcut(QtGui.QKeySequence("Ctrl+T"), self, self.setEncDecSafe) #
		QtGui.QShortcut(QtGui.QKeySequence("Ctrl+W"), self, self.setEncDecWipe) #
		QtGui.QShortcut(QtGui.QKeySequence("Ctrl+M"), self, self.setEncFn) #
		QtGui.QShortcut(QtGui.QKeySequence("Ctrl+N"), self, self.setDecFn) #

		self.clipboard = QtGui.QApplication.clipboard()
		self.textBrowser.selectionChanged.connect(self.selectionChanged)


	def printAbout(self):
		"""
		Show window with about and version information.
		"""
		msgBox = QtGui.QMessageBox(QtGui.QMessageBox.Information, "About",
			"About <b>TrezorSymmetricFileEncryption</b>: <br><br>TrezorSymmetricFileEncryption " +
			"is a file encryption and decryption tool using a Trezor hardware "
			"device for safety and security. Symmetric AES cryptography is used "
			"at its core. <br><br>" +
			"<b>Version: </b>" + basics.TSFEVERSION +
			" from " + basics.TSFEVERSIONTEXT)
		msgBox.setIconPixmap(QPixmap("icons/TrezorSymmetricFileEncryption.216x100.svg"))
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
			reportLogging("You have selected the option `--obfuscate`. "
				"After encrypting the file(s) the encrypted file(s) will be "
				"renamed to encrypted, strange looking names. This hides the meta-data,"
				"i.e. the filename.", logging.INFO,
				"Arguments", self.settings, self.logger, self)

	def validateEnc2(self):
		if self.checkBoxEnc2.isChecked():
				reportLogging("You have selected the option `--twice`. "
				"Files will be encrypted not on your computer but on the Trezor "
				"device itself. This is slow. It takes 75 seconds for 1M. "
				"In other words, 0.8M/min. "
				"Remove this option if the file is too big or "
				"you do not want to wait.", logging.INFO,
				"Dangerous arguments", self.settings, self.logger, self)

	def validateEncS(self):
		if self.checkBoxEncS.isChecked():
				reportLogging("You have selected the option `--safety`. "
				"After encrypting the file(s) the file(s) will immediately "
				"be decrypted and the output compared to the original file(s). "
				"This safety check definitely guarantees that all is well.", logging.INFO,
				"Arguments", self.settings, self.logger, self)

	def validateEncW(self):
		if self.checkBoxEncW.isChecked():
				reportLogging("You have selected the option `--wipe`. "
				"The original plaintext files will "
				"be shredded and permanently deleted after encryption. "
				"Remove this option if you are uncertain or don't understand.", logging.WARN,
				"Dangerous arguments", self.settings, self.logger, self)

	def validateDecS(self):
		if self.checkBoxEncS.isChecked():
				reportLogging("You have selected the option `--safety`. "
				"After decrypting the file(s) the file(s) will immediately "
				"be encrypted and the output compared to the original file(s). "
				"This safety check definitely guarantees that all is well.", logging.INFO,
				"Arguments", self.settings, self.logger, self)

	def validateDecW(self):
		if self.checkBoxDecW.isChecked():
				reportLogging("You have selected the option `--wipe`. "
				"The encrypted files will be shredded and permanently deleted after decryption. "
				"Remove this option if you are uncertain or don't understand.", logging.WARN,
				"Dangerous arguments", self.settings, self.logger, self)

	def selectionChanged(self):
		"""
		called whenever selected text in textarea is changed
		"""
		# self.textBrowser.copy() # copy selected to clipboard
		# reportLogging("Copied text to clipboard: %s" % self.clipboard.text(),
		#	logging.DEBUG, "Clipboard", self.settings, self.logger, self)
		""" empty """

	def copy2Clipboard(self):
		self.textBrowser.copy() # copy selected to clipboard
		# This is content from the Status textarea, so no secrets here, we can log it
		reportLogging("Copied text to clipboard: %s" % self.clipboard.text(), logging.DEBUG,
			"Clipboard", self.settings, self.logger, self)

	def setVersion(self, version):
		self.version = version
		self.description1 = """<!DOCTYPE html><html><head>
			<body style="font-size:11pt; font-weight:400; font-style:normal;">
			<b>Welcome to TrezorSymmetricFileEncryption</b>, version
			""" + self.version + """<br>En/decrypting once is fast.
			En/decrypting twice is slow on large files.
			<br>If you lose your master passphrase you will not be able to
			decrypt your file(s).<br>You may leave the master passphrase empty.
			"""

	def setDescription(self, extradescription):
		self.textBrowser.setHtml(s2q(self.description1 + extradescription + self.description3))

	def appendDescription(self, extradescription):
		"""
		@param extradescription: text in HTML format, use </br> for linebreaks
		"""
		self.description2 += extradescription
		self.textBrowser.setHtml(s2q(self.description1 + self.description2 + self.description3))

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
		return self.masterEdit1.text()

	def setPw1(self, arg):
		self.masterEdit1.setText(s2q(arg))

	def pw2(self):
		return self.masterEdit2.text()

	def setPw2(self, arg):
		self.masterEdit2.setText(s2q(arg))

	def setSelectedFile(self, fileNames):
		"""
		Takes a py list as input and concatenates it and
		then places it into the single-line text field
		"""
		filenamesconcat = ""
		for file in fileNames:
			head, tail = os.path.split(file)
			filenamesconcat += '"' + tail + '"' + ' '
		self.selectedFileEdit.setText(s2q(filenamesconcat))

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

	def validate(self):
		"""
		Enable OK/Apply buttons only if both master and backup are repeated
		without typo and some file is selected and
		exactly a single decrypt/encrypt option from the radio buttons is set.
		And only when Encrypt is selected.
		On decrypt passphrase does not need to be specified twice.
		"""
		if self.dec() or self.decFn():
			self.labelPw2.setText(s2q("Neither needed nor used to decrypt"))
		else:
			self.labelPw2.setText(s2q("Repeat master passphrase for Trezor"))

		same = self.pw1() == self.pw2()
		fileSelected = not self.selectedFileEdit.text().isEmpty()

		# QtGui.QDialogButtonBox.Ok
		button = self.buttonBox.button(QtGui.QDialogButtonBox.Apply)
		button.setEnabled(fileSelected and (same or self.dec() or self.decFn()))
		return fileSelected and (same or self.dec() or self.decFn())

#	def handleButtonClick(self, button):
#		sb = self.buttonBox.standardButton(button)
#		if sb == QtGui.QDialogButtonBox.Apply:
#			processAll(self.trezor, self.settings, self.fileMap, self.logger, self) #
#		# elif sb == QtGui.QDialogButtonBox.Reset:
#		#	reportLogging("Reset Clicked, quitting now...", logging.DEBUG,
#		#		"UI", self.settings, self.logger, self)

	def accept(self):
		"""
		Apply button was pressed
		"""
		if self.validate():
			reportLogging("Apply was called by user request. Start processing now.",
				logging.DEBUG, "GUI IO", self.settings, self.logger, self)
			processAll(self.trezor, self.settings, self.fileMap, self.logger, self) #
		else:
			reportLogging("Apply was called by user request. Apply is denied. "
				"User input is not valid for processing. Did you select a file?",
				logging.DEBUG, "GUI IO", self.settings, self.logger, self)

	# Don't set up a reject() method, it is automatically created.
	# If created here again it would overwrite the default one
	# def reject(self):
	#	self.close()

	def selectFile(self):
		"""
		Show file dialog and return file(s) user has chosen.
		"""
		path = QtCore.QDir.currentPath()
		dialog = QtGui.QFileDialog(self, "Select file(s)",
			path, "(*)")
		dialog.setFileMode(QtGui.QFileDialog.ExistingFiles);
		dialog.setAcceptMode(QtGui.QFileDialog.AcceptOpen)

		res = dialog.exec_()
		if not res:
			return

		qFnameList = dialog.selectedFiles() # QStringList
		self.fileNames = str(qFnameList.join("<join>")).split("<join>") # convert to Py list
		reportLogging("Selected files are: %s" % str(self.fileNames),
			logging.DEBUG, "GUI IO", self.settings, self.logger, self)
		self.setSelectedFile(self.fileNames)

class EnterPinDialog(QtGui.QDialog, Ui_EnterPinDialog):

	def __init__(self):
		QtGui.QDialog.__init__(self)
		self.setupUi(self)

		self.pb1.clicked.connect(self.pinpadPressed)
		self.pb2.clicked.connect(self.pinpadPressed)
		self.pb3.clicked.connect(self.pinpadPressed)
		self.pb4.clicked.connect(self.pinpadPressed)
		self.pb5.clicked.connect(self.pinpadPressed)
		self.pb6.clicked.connect(self.pinpadPressed)
		self.pb7.clicked.connect(self.pinpadPressed)
		self.pb8.clicked.connect(self.pinpadPressed)
		self.pb9.clicked.connect(self.pinpadPressed)

	def pin(self):
		return self.pinEdit.text()

	def pinpadPressed(self):
		sender = self.sender()
		objName = sender.objectName()
		digit = objName[-1]
		self.pinEdit.setText(self.pinEdit.text() + digit)

class TrezorChooserDialog(QtGui.QDialog, Ui_TrezorChooserDialog):

	def __init__(self, deviceMap):
		"""
		Create dialog and fill it with labels from deviceMap

		@param deviceMap: dict device string -> device label
		"""
		QtGui.QDialog.__init__(self)
		self.setupUi(self)

		for deviceStr, label in deviceMap.items():
			item = QtGui.QListWidgetItem(label)
			item.setData(QtCore.Qt.UserRole, QtCore.QVariant(deviceStr))
			self.trezorList.addItem(item)
		self.trezorList.setCurrentRow(0)

	def chosenDeviceStr(self):
		"""
		Returns device string of chosen Trezor
		"""
		itemData = self.trezorList.currentItem().data(QtCore.Qt.UserRole)
		deviceStr = str(itemData.toString())
		return deviceStr
