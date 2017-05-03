from PyQt4 import QtGui, QtCore

import os
import base64
import hashlib

from ui_trezor_passphrase_dialog import Ui_TrezorPassphraseDialog
from ui_dialog import Ui_Dialog
from ui_enter_pin_dialog import Ui_EnterPinDialog
from ui_trezor_chooser_dialog import Ui_TrezorChooserDialog

from encoding import q2s, s2q

class TrezorPassphraseDialog(QtGui.QDialog, Ui_TrezorPassphraseDialog):

	def __init__(self):
		QtGui.QDialog.__init__(self)
		self.setupUi(self)

	def passphrase(self):
		return self.passphraseEdit.text()

class Dialog(QtGui.QDialog, Ui_Dialog):

	def __init__(self):
		QtGui.QDialog.__init__(self)
		self.setupUi(self)
		self.radioButton1.toggled.connect(self.validate)
		self.radioButton2.toggled.connect(self.validate)
		self.radioButton3.toggled.connect(self.validate)
		self.masterEdit1.textChanged.connect(self.validate)
		self.masterEdit2.textChanged.connect(self.validate)
		self.selectedFileEdit.textChanged.connect(self.validate)
		self.selectedFileButton.clicked.connect(self.selectFile)
		self.validate()
		self.version = ""
		self.fileNames = []

	def setVersion(self, version):
		self.version = version

	def setDescription(self, extradescription):
		displayHtmlText1 = """<!DOCTYPE html><html><head><body style="font-size:12pt; font-weight:400; font-style:normal;">
			<b>Welcome to TrezorSymmetricFileEncryption. </b></p>
			<p style="font-size:11pt;">This is version
			"""
		displayHtmlText2 = """.<p>
			You need to choose a master passphrase that will be used as a Trezor passphrase to encrypt and decrypt files. If forgotten, there's only bruteforcing left. You may leave it empty.</p>
			"""
		displayHtmlText3 = "</body></html>"
		self.textBrowser.setHtml(s2q(displayHtmlText1 + self.version + displayHtmlText2 + extradescription + displayHtmlText3))

	def enc(self):
		"""
		Returns True if radio button for option "encrypt with plaintext filename" is selected
		"""
		return self.radioButton1.isChecked()

	def setEnc(self, arg):
		self.radioButton1.setChecked(arg)

	def encObf(self):
		"""
		Returns True if radio button for option "encrypt and obfuscate filename" is selected
		"""
		return self.radioButton2.isChecked()

	def setEncObf(self, arg):
		self.radioButton2.setChecked(arg)

	def dec(self):
		"""
		Returns True if radio button for option "decrypt" is selected
		"""
		return self.radioButton3.isChecked()

	def setDec(self, arg):
		self.radioButton3.setChecked(arg)

	def decFn(self):
		"""
		Returns True if radio button for option "decrypt only filename" is selected
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
		Takes a py list as input and concatenates it and then places it into the single-line text field
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
		Most likely you want a nice list of full filenames with paths, so use selectedFiles()
		"""
		return self.selectedFileEdit.text()

	def selectedFiles(self):
		"""
		Returns a list of full filenames with paths
		"""
		return self.fileNames

	def validate(self):
		"""
		Enable OK button only if both master and backup are repeated
		without typo and some password file is selected and
		exactly a single decrypt/encrypt option from the radio buttons is set.
		"""
		same = self.pw1() == self.pw2()
		fileSelected = not self.selectedFileEdit.text().isEmpty()

		button = self.buttonBox.button(QtGui.QDialogButtonBox.Ok)
		# exactly one is set
		#  and (self.enc() ^ self.encObf() ^ self.dec()) and not (self.enc() and self.encObf() and self.dec())
		button.setEnabled(same and fileSelected)

	def selectFile(self):
		"""
		Show file dialog and return file user chose to store the
		encrypted password database.
		"""
		path = QtCore.QDir.currentPath()
		dialog = QtGui.QFileDialog(self, "Select password database file",
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
