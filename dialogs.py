from PyQt4 import QtGui, QtCore

import os
import os.path
import base64
import hashlib

from ui_trezor_passphrase_dialog import Ui_TrezorPassphraseDialog
from ui_dialog import Ui_Dialog
from ui_enter_pin_dialog import Ui_EnterPinDialog
from ui_trezor_chooser_dialog import Ui_TrezorChooserDialog

from encoding import q2s, s2q
from processing import processAllFromApply

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

		self.radioButton1.toggled.connect(self.validate)
		self.radioButton2.toggled.connect(self.validate)
		self.radioButton3.toggled.connect(self.validate)
		self.radioButton4.toggled.connect(self.validate)
		self.radioButton5.toggled.connect(self.validate)
		self.radioButton6.toggled.connect(self.validate)
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

		self.clipboard = QtGui.QApplication.clipboard()
		self.textBrowser.selectionChanged.connect(self.selectionChanged)

	def selectionChanged(self):
		"""
		called whenever selected text in textarea is changed
		"""
		# self.textBrowser.copy() # copy selected to clipboard
		# print self.clipboard.text() # print clipboard
		""" empty """

	def copy2Clipboard(self):
		self.textBrowser.copy() # copy selected to clipboard
		self.logger.debug("Copied to clipboard: %s", self.clipboard.text()) # print clipboard

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

	def enc(self):
		"""
		Returns True if radio button for option "encrypt with plaintext filename"
		is selected
		"""
		return self.radioButton1.isChecked()

	def setEnc(self, arg):
		self.radioButton1.setChecked(arg)

	def encObf(self):
		"""
		Returns True if radio button for option "encrypt and obfuscate filename"
		is selected
		"""
		return self.radioButton2.isChecked()

	def setEncObf(self, arg):
		self.radioButton2.setChecked(arg)

	def setEncTwice(self, arg):
		self.radioButton5.setChecked(arg)

	def setEncTwiceObf(self, arg):
		self.radioButton6.setChecked(arg)

	def encTwice(self):
		return self.radioButton5.isChecked()

	def encTwiceObf(self):
		return self.radioButton6.isChecked()

	def dec(self):
		"""
		Returns True if radio button for option "decrypt" is selected
		"""
		return self.radioButton3.isChecked()

	def setDec(self, arg):
		self.radioButton3.setChecked(arg)

	def decFn(self):
		"""
		Returns True if radio button for option "decrypt only filename" is
		selected
		"""
		return self.radioButton4.isChecked()

	def setDecFn(self, arg):
		self.radioButton4.setChecked(arg)

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
		# exactly one is set
		#  and (self.enc() ^ self.encObf() ^ self.dec()) and not (self.enc() and self.encObf() and self.dec())
		button.setEnabled(fileSelected and (same or self.dec() or self.decFn()))
		return fileSelected and (same or self.dec() or self.decFn())

#	def handleButtonClick(self, button):
#		sb = self.buttonBox.standardButton(button)
#		if sb == QtGui.QDialogButtonBox.Apply:
#			feedback = processAllFromApply(self, self.trezor, self.settings, self.fileMap, self.logger) #
#			self.appendDescription(feedback)
#		# elif sb == QtGui.QDialogButtonBox.Reset:
#		#	print('Reset Clicked, quitting now...')

	def accept(self):
		"""
		Apply button was pinpadPressed
		"""
		if self.validate():
			self.logger.debug("Apply was called by user request. Start processing now.")
			feedback = processAllFromApply(self, self.trezor, self.settings, self.fileMap, self.logger) #
			self.appendDescription(feedback)
			# move the cursor to the end of the text, scroll to the bottom
			cursor = self.textBrowser.textCursor()
			cursor.setPosition(len(self.textBrowser.toPlainText()))
			self.textBrowser.ensureCursorVisible()
			self.textBrowser.setTextCursor(cursor)
		else:
			self.logger.debug("Apply was called by user request. Apply is denied. User input is not valid for processing. Did you select a file?")

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
		print "Selected files are: ", self.fileNames
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
