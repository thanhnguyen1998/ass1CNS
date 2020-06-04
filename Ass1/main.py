import os
import sys
from PyQt5 import uic
from PyQt5.QtGui import *
from PyQt5.QtCore import *
import rsa
import file_manager
from PyQt5.QtWidgets import QApplication, QDialog, QFileDialog, QLabel, QMainWindow, QPushButton, QVBoxLayout

AES = 0
DES3 = 1

qtCreatorFile = "ui.ui" # Enter file here. 
Ui_MainWindow, QtBaseClass = uic.loadUiType(qtCreatorFile)
 
class MyApp(QMainWindow, Ui_MainWindow):
    def __init__(self):
        QMainWindow.__init__(self)
        Ui_MainWindow.__init__(self)
        self.setupUi(self)

        self.e_browse_input.clicked.connect(lambda: self.getFileNametoTextBox(self.e_input_path))
        self.e_browse_output.clicked.connect(lambda: self.getFileNametoTextBox(self.e_output_path,True))
        self.e_browse_key.clicked.connect(lambda: self.getFileNametoTextBox(self.e_key,True))
        self.e_encrypt.clicked.connect(self.encryptFile)
        self.e_generate.clicked.connect(self.generateRSAKey)

        self.d_browse_input.clicked.connect(lambda: self.getFileNametoTextBox(self.d_input_path))
        self.d_browse_output.clicked.connect(lambda: self.getFileNametoTextBox(self.d_output_path,True))
        self.d_browse_key.clicked.connect(lambda: self.getFileNametoTextBox(self.d_key,True))
        self.d_decrypt.clicked.connect(self.decryptFile)

    def encryptFile(self):
        #Kiem tra thong tin duong dan da duoc dien day du
        if self.e_input_path.toPlainText() and self.e_key.toPlainText() and self.e_output_path.toPlainText():

            #Kiem tra 1 trong so cac radio option duoc chon
            #
            if self.e_des_button.isChecked() or self.e_aes_button.isChecked() or self.e_rsa_button.isChecked():
                if self.e_des_button.isChecked():
                    file_manager.encrypt_file(self.e_input_path.toPlainText(),self.e_output_path.toPlainText(),self.e_key.toPlainText(),DES3)
                    isBigFile = False
                elif self.e_aes_button.isChecked():
                    file_manager.encrypt_file(self.e_input_path.toPlainText(),self.e_output_path.toPlainText(),self.e_key.toPlainText(),AES)
                    isBigFile = False
                else:
                    try:
                        file_manager.encrypt_file_rsa(self.e_input_path.toPlainText(),self.e_key.toPlainText(),self.e_output_path.toPlainText())
                    except ValueError:
                        isBigFile = True
                    isBigFile = False
                if isBigFile:
                    self.showdialog("RSA Algorithms: This file is too big")
                else:
                    self.showdialog("Encrypt file success !!")

            else:
                self.showdialog("No algorithms is chosen!!")
        else:
            self.showdialog("Missing some file/folder path!!")
    def decryptFile(self):
        #Kiem tra thong tin duong dan da duoc dien day du
        if self.d_input_path.toPlainText() and self.d_key.toPlainText() and self.d_output_path.toPlainText():

            #Kiem tra 1 trong so cac radio option duoc chon
            #
            if self.d_des_button.isChecked() or self.d_aes_button.isChecked() or self.d_rsa_button.isChecked():
                if self.d_des_button.isChecked():
                    success = file_manager.decrypt_file(self.d_input_path.toPlainText(),self.d_output_path.toPlainText(),self.d_key.toPlainText(),DES3)
                elif self.d_aes_button.isChecked():
                    success = file_manager.decrypt_file(self.d_input_path.toPlainText(),self.d_output_path.toPlainText(),self.d_key.toPlainText(),AES)
                else:

                    success = file_manager.decrypt_file_rsa(self.d_input_path.toPlainText(),self.d_key.toPlainText(),self.d_output_path.toPlainText())
                
                if success:
                    self.showdialog("Decrypt file success, hash value is correct. This is origin file")
                else:
                    self.showdialog("Decrypt file success, hash value is incorrect. This is not origin file")
            else:
                self.showdialog("No algorithms are chosen")
        else:
            self.showdialog("Missing some file/folder path")

    

    def generateRSAKey(self):
        str = self.getFolderName()
        rsa.generate_key(str)
        self.showdialog("Key have been save at ..." + str)

    def showdialog(self,message):
        dialog = QDialog()
        button = QPushButton("OK")
        text = QLabel(message)
        text.setAlignment(Qt.AlignCenter)
        text.setWordWrap(True)

        vbox = QVBoxLayout()
        vbox.addWidget(text)
        vbox.addStretch()
        vbox.addWidget(button)

        dialog.setLayout(vbox)
        dialog.setMaximumSize(250,150)
        dialog.setMinimumSize(250,150)
        dialog.setWindowTitle("Notification")
        dialog.setWindowModality(2)

        button.clicked.connect(dialog.reject)

        dialog.exec_()

    def getFileNametoTextBox(self,textBox,isFolder = False):
        dialog = QFileDialog()
        if isFolder:
            dialog.setFileMode(QFileDialog.Directory)
        else:
            dialog.setFileMode(QFileDialog.AnyFile)
        
        filenames = []
        if dialog.exec():
            filenames = dialog.selectedFiles()
        if (filenames):
            textBox.setPlainText(filenames[0])
   
    def getFolderName(self):
        return str(QFileDialog.getExistingDirectory(self, "Select Directory"))

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MyApp()
    window.show()
    sys.exit(app.exec_())