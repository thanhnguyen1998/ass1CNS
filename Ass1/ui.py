# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'ui.ui'
#
# Created by: PyQt5 UI code generator 5.13.0
#
# WARNING! All changes made in this file will be lost!


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_Cryto(object):
    def setupUi(self, Cryto):
        Cryto.setObjectName("Cryto")
        Cryto.resize(800, 600)
        Cryto.setAnimated(True)
        self.centralwidget = QtWidgets.QWidget(Cryto)
        self.centralwidget.setObjectName("centralwidget")
        self.tabWidget = QtWidgets.QTabWidget(self.centralwidget)
        self.tabWidget.setGeometry(QtCore.QRect(0, 0, 841, 631))
        self.tabWidget.setObjectName("tabWidget")
        self.Encrypt_2 = QtWidgets.QWidget()
        self.Encrypt_2.setObjectName("Encrypt_2")
        self.e_browse_input = QtWidgets.QPushButton(self.Encrypt_2)
        self.e_browse_input.setGeometry(QtCore.QRect(580, 230, 75, 23))
        self.e_browse_input.setObjectName("e_browse_input")
        self.e_des_button = QtWidgets.QRadioButton(self.Encrypt_2)
        self.e_des_button.setGeometry(QtCore.QRect(80, 80, 82, 17))
        self.e_des_button.setObjectName("e_des_button")
        self.e_aes_button = QtWidgets.QRadioButton(self.Encrypt_2)
        self.e_aes_button.setGeometry(QtCore.QRect(80, 110, 82, 17))
        self.e_aes_button.setObjectName("e_aes_button")
        self.e_rsa_button = QtWidgets.QRadioButton(self.Encrypt_2)
        self.e_rsa_button.setGeometry(QtCore.QRect(80, 140, 82, 17))
        self.e_rsa_button.setObjectName("e_rsa_button")
        self.FileInputL = QtWidgets.QLabel(self.Encrypt_2)
        self.FileInputL.setGeometry(QtCore.QRect(80, 230, 61, 16))
        self.FileInputL.setObjectName("FileInputL")
        self.KeyL = QtWidgets.QLabel(self.Encrypt_2)
        self.KeyL.setGeometry(QtCore.QRect(80, 290, 47, 13))
        self.KeyL.setObjectName("KeyL")
        self.FileOutputL = QtWidgets.QLabel(self.Encrypt_2)
        self.FileOutputL.setGeometry(QtCore.QRect(80, 350, 71, 16))
        self.FileOutputL.setObjectName("FileOutputL")
        self.e_browse_output = QtWidgets.QPushButton(self.Encrypt_2)
        self.e_browse_output.setGeometry(QtCore.QRect(580, 350, 75, 23))
        self.e_browse_output.setObjectName("e_browse_output")
        self.e_encrypt = QtWidgets.QPushButton(self.Encrypt_2)
        self.e_encrypt.setGeometry(QtCore.QRect(290, 460, 191, 41))
        self.e_encrypt.setObjectName("e_encrypt")
        self.e_input_path = QtWidgets.QPlainTextEdit(self.Encrypt_2)
        self.e_input_path.setGeometry(QtCore.QRect(140, 230, 421, 21))
        self.e_input_path.setObjectName("e_input_path")
        self.e_key = QtWidgets.QPlainTextEdit(self.Encrypt_2)
        self.e_key.setGeometry(QtCore.QRect(140, 290, 421, 21))
        self.e_key.setObjectName("e_key")
        self.e_output_path = QtWidgets.QPlainTextEdit(self.Encrypt_2)
        self.e_output_path.setGeometry(QtCore.QRect(140, 350, 421, 21))
        self.e_output_path.setObjectName("e_output_path")
        self.label = QtWidgets.QLabel(self.Encrypt_2)
        self.label.setGeometry(QtCore.QRect(60, 30, 501, 21))
        font = QtGui.QFont()
        font.setFamily("Microsoft JhengHei UI")
        font.setPointSize(12)
        self.label.setFont(font)
        self.label.setObjectName("label")
        self.e_generate = QtWidgets.QPushButton(self.Encrypt_2)
        self.e_generate.setGeometry(QtCore.QRect(230, 410, 101, 23))
        self.e_generate.setObjectName("e_generate")
        self.label_3 = QtWidgets.QLabel(self.Encrypt_2)
        self.label_3.setGeometry(QtCore.QRect(100, 410, 111, 16))
        self.label_3.setObjectName("label_3")
        self.e_browse_key = QtWidgets.QPushButton(self.Encrypt_2)
        self.e_browse_key.setGeometry(QtCore.QRect(580, 290, 75, 23))
        self.e_browse_key.setObjectName("e_browse_key")
        self.tabWidget.addTab(self.Encrypt_2, "")
        self.Decrypt = QtWidgets.QWidget()
        self.Decrypt.setObjectName("Decrypt")
        self.d_input_path = QtWidgets.QPlainTextEdit(self.Decrypt)
        self.d_input_path.setGeometry(QtCore.QRect(140, 230, 421, 21))
        self.d_input_path.setObjectName("d_input_path")
        self.d_browse_output = QtWidgets.QPushButton(self.Decrypt)
        self.d_browse_output.setGeometry(QtCore.QRect(580, 350, 75, 23))
        self.d_browse_output.setObjectName("d_browse_output")
        self.KeyL_4 = QtWidgets.QLabel(self.Decrypt)
        self.KeyL_4.setGeometry(QtCore.QRect(80, 290, 47, 13))
        self.KeyL_4.setObjectName("KeyL_4")
        self.d_browse_input = QtWidgets.QPushButton(self.Decrypt)
        self.d_browse_input.setGeometry(QtCore.QRect(580, 230, 75, 23))
        self.d_browse_input.setObjectName("d_browse_input")
        self.d_decrypt = QtWidgets.QPushButton(self.Decrypt)
        self.d_decrypt.setGeometry(QtCore.QRect(290, 460, 191, 41))
        self.d_decrypt.setObjectName("d_decrypt")
        self.FileInputL_4 = QtWidgets.QLabel(self.Decrypt)
        self.FileInputL_4.setGeometry(QtCore.QRect(80, 230, 61, 16))
        self.FileInputL_4.setObjectName("FileInputL_4")
        self.d_output_path = QtWidgets.QPlainTextEdit(self.Decrypt)
        self.d_output_path.setGeometry(QtCore.QRect(140, 350, 421, 21))
        self.d_output_path.setObjectName("d_output_path")
        self.d_key = QtWidgets.QPlainTextEdit(self.Decrypt)
        self.d_key.setGeometry(QtCore.QRect(140, 290, 421, 21))
        self.d_key.setObjectName("d_key")
        self.FileOutputL_4 = QtWidgets.QLabel(self.Decrypt)
        self.FileOutputL_4.setGeometry(QtCore.QRect(80, 350, 71, 16))
        self.FileOutputL_4.setObjectName("FileOutputL_4")
        self.d_des_button = QtWidgets.QRadioButton(self.Decrypt)
        self.d_des_button.setGeometry(QtCore.QRect(80, 80, 82, 17))
        self.d_des_button.setObjectName("d_des_button")
        self.d_rsa_button = QtWidgets.QRadioButton(self.Decrypt)
        self.d_rsa_button.setGeometry(QtCore.QRect(80, 140, 82, 17))
        self.d_rsa_button.setObjectName("d_rsa_button")
        self.d_aes_button = QtWidgets.QRadioButton(self.Decrypt)
        self.d_aes_button.setGeometry(QtCore.QRect(80, 110, 82, 17))
        self.d_aes_button.setObjectName("d_aes_button")
        self.label_2 = QtWidgets.QLabel(self.Decrypt)
        self.label_2.setGeometry(QtCore.QRect(60, 30, 501, 21))
        font = QtGui.QFont()
        font.setFamily("Microsoft JhengHei UI")
        font.setPointSize(12)
        self.label_2.setFont(font)
        self.label_2.setObjectName("label_2")
        self.d_browse_key = QtWidgets.QPushButton(self.Decrypt)
        self.d_browse_key.setGeometry(QtCore.QRect(580, 290, 75, 23))
        self.d_browse_key.setObjectName("d_browse_key")
        self.tabWidget.addTab(self.Decrypt, "")
        Cryto.setCentralWidget(self.centralwidget)

        self.retranslateUi(Cryto)
        self.tabWidget.setCurrentIndex(1)
        QtCore.QMetaObject.connectSlotsByName(Cryto)

    def retranslateUi(self, Cryto):
        _translate = QtCore.QCoreApplication.translate
        Cryto.setWindowTitle(_translate("Cryto", "Crypto"))
        self.e_browse_input.setText(_translate("Cryto", "Browse"))
        self.e_des_button.setText(_translate("Cryto", "DES"))
        self.e_aes_button.setText(_translate("Cryto", "AES"))
        self.e_rsa_button.setText(_translate("Cryto", "RSA"))
        self.FileInputL.setText(_translate("Cryto", "File input :"))
        self.KeyL.setText(_translate("Cryto", "Key :"))
        self.FileOutputL.setText(_translate("Cryto", "File output :"))
        self.e_browse_output.setText(_translate("Cryto", "Browse"))
        self.e_encrypt.setText(_translate("Cryto", "ENCRYPT"))
        self.label.setText(_translate("Cryto", "Choose a algorithm :"))
        self.e_generate.setText(_translate("Cryto", "Generate"))
        self.label_3.setText(_translate("Cryto", "Random key for RSA :"))
        self.e_browse_key.setText(_translate("Cryto", "Browse"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.Encrypt_2), _translate("Cryto", "ENCRYPT"))
        self.d_browse_output.setText(_translate("Cryto", "Browse"))
        self.KeyL_4.setText(_translate("Cryto", "Key :"))
        self.d_browse_input.setText(_translate("Cryto", "Browse"))
        self.d_decrypt.setText(_translate("Cryto", "DECRYPT"))
        self.FileInputL_4.setText(_translate("Cryto", "File input :"))
        self.FileOutputL_4.setText(_translate("Cryto", "File output :"))
        self.d_des_button.setText(_translate("Cryto", "DES"))
        self.d_rsa_button.setText(_translate("Cryto", "RSA"))
        self.d_aes_button.setText(_translate("Cryto", "AES"))
        self.label_2.setText(_translate("Cryto", "Choose a algorithm :"))
        self.d_browse_key.setText(_translate("Cryto", "Browse"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.Decrypt), _translate("Cryto", "DECRYPT"))


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    Cryto = QtWidgets.QMainWindow()
    ui = Ui_Cryto()
    ui.setupUi(Cryto)
    Cryto.show()
    sys.exit(app.exec_())
