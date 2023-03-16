import sys
from PyQt6.QtWidgets import QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTextEdit, QFileDialog
from PyQt6 import QtWidgets
import Utils
import time


class AESWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        # Tạo TabWidget
        self.tab_widget = QTabWidget()
        self.setCentralWidget(self.tab_widget)

        # Tạo Tab cho Encrypt
        self.encrypt_tab = QWidget()
        self.tab_widget.addTab(self.encrypt_tab, "Encrypt")

        # Thiết kế giao diện cho Tab Encrypt
        self.plain_label = QLabel("Plain Text")
        self.plain_text = QTextEdit()
        self.key_label = QLabel("Key")
        self.key_text = QtWidgets.QLineEdit()
        self.key_text.setMaxLength(32)
        self.key_text.setFixedHeight(50)
        self.radio_button_128 = QtWidgets.QRadioButton("128bits")
        self.radio_button_128.setChecked(True)
        self.radio_button_128.type = 128
        self.radio_button_128.released.connect(self.on_clicked)
        self.radio_button_192 = QtWidgets.QRadioButton("192bits")
        self.radio_button_192.type = 192
        self.radio_button_192.released.connect(self.on_clicked)
        self.radio_button_256 = QtWidgets.QRadioButton("256bits")
        self.radio_button_256.type = 256
        self.radio_button_256.released.connect(self.on_clicked)

        self.ciphertext_label = QLabel('Ciphertext:')
        self.ciphertext_edit = QTextEdit()

        self.take_time = QLabel("Take time: 0 seconds")

        self.encrypt_button = QPushButton("Encrypt")
        self.encrypt_button.clicked.connect(self.encrypt)
        self.import_plain_text_button = QPushButton("Import")
        self.import_plain_text_button.clicked.connect(self.import_plain_text_file)
        self.export_cipher_text_button = QPushButton("Export")
        self.export_cipher_text_button.clicked.connect(self.export_cipher_text_file)

        layout = QVBoxLayout()
        layout.addWidget(self.plain_label)
        layout.addWidget(self.plain_text)

        # Thêm button "Import" vào Tab Encrypt
        hbox = QHBoxLayout()
        hbox.addWidget(self.import_plain_text_button)
        hbox.addStretch()
        layout.addLayout(hbox)
        layout.addWidget(self.key_label)
        layout.addWidget(self.key_text)
        hbox = QHBoxLayout()
        hbox.addWidget(self.radio_button_128)
        hbox.addWidget(self.radio_button_192)
        hbox.addWidget(self.radio_button_256)
        hbox.addStretch()
        layout.addLayout(hbox)
        layout.addWidget(self.ciphertext_label)
        layout.addWidget(self.ciphertext_edit)
        hbox = QHBoxLayout()
        hbox.addWidget(self.export_cipher_text_button)
        hbox.addStretch()
        layout.addLayout(hbox)
        layout.addWidget(self.take_time)
        layout.addWidget(self.encrypt_button)
        self.encrypt_tab.setLayout(layout)

        # Tạo Tab cho Decrypt
        self.decrypt_tab = QWidget()
        self.tab_widget.addTab(self.decrypt_tab, "Decrypt")

        # Thiết kế giao diện cho Tab Decrypt
        self.cipher_text_label2 = QLabel("Cipher Text")
        self.cipher_text_edit2 = QTextEdit()

        self.key_label2 = QLabel("Key")
        self.key_text2 = QTextEdit()
        self.key_text2.setFixedHeight(50)

        self.take_time2 = QLabel("Take time: 0 seconds")

        self.plaintext_label2 = QLabel('Plaintext:')
        self.plaintext_edit2 = QTextEdit()

        self.decrypt_button = QPushButton("Decrypt")
        self.decrypt_button.clicked.connect(self.decrypt)
        self.import_cipher_text_button = QPushButton("Import")
        self.import_cipher_text_button.clicked.connect(self.import_cipher_text_file)
        self.export_plain_text_button = QPushButton("Export")
        self.export_plain_text_button.clicked.connect(self.export_plain_text_file)

        layout2 = QVBoxLayout()
        layout2.addWidget(self.cipher_text_label2)
        layout2.addWidget(self.cipher_text_edit2)

        # Thêm button "Import" vào Tab Decrypt
        hbox = QHBoxLayout()
        hbox.addWidget(self.import_cipher_text_button)
        hbox.addStretch()
        layout2.addLayout(hbox)

        layout2.addWidget(self.key_label2)
        layout2.addWidget(self.key_text2)

        layout2.addWidget(self.plaintext_label2)
        layout2.addWidget(self.plaintext_edit2)
        hbox = QHBoxLayout()
        hbox.addWidget(self.export_plain_text_button)
        hbox.addStretch()
        layout2.addLayout(hbox)
        layout2.addWidget(self.take_time2)
        layout2.addWidget(self.decrypt_button)

        self.decrypt_tab.setLayout(layout2)

        # Thiết lập các thuộc tính khác của UI
        self.setGeometry(100, 100, 600, 400)
        self.setWindowTitle('AES Encryption/Decryption')

    def on_clicked(self):
        radio_button = self.sender()
        leng = int(radio_button.type)//4
        self.key_text.setMaxLength(leng)

    def encrypt(self):
        """
        Hàm xử lý khi bấm nút encrypt
        :return: thời gian mã hóa
        """
        plaintext = self.plain_text.toPlainText()
        key = self.key_text.toPlainText()
        if plaintext == "" or key == "":
            error_dialog = QtWidgets.QErrorMessage()
            error_dialog.showMessage("Plaintext or key field empty!")
            error_dialog.exec()
            self.take_time.setText(f"Take time: 0 seconds")
        else:
            start_time = time.time()
            blocks = Utils.preprocess_data_input(plaintext)
            cipher_blocks = []
            for block in blocks:
                tmp = Utils.encrypt(block, key)
                cipher_blocks.append(tmp)
            cipher_blocks = [Utils.to_ascii(i) for i in cipher_blocks]  # chuyen hex sang ki tu
            ciphertext = "".join(cipher_blocks)
            end_time = time.time()
            self.ciphertext_edit.setText(ciphertext)
            self.take_time.setText(f"Take time: {round(end_time - start_time, 4)} seconds")


    def decrypt(self):
        """
        Hàm xử lý khi bấm nút decrypt
        :return: thời gian mã hóa
        """
        ciphertext = self.cipher_text_edit2.toPlainText()
        key = self.key_text2.toPlainText()
        if ciphertext == "" or key == "":
            error_dialog = QtWidgets.QErrorMessage()
            error_dialog.showMessage("Ciphertext or key field empty!")
            error_dialog.exec()
            self.take_time2.setText(f"Take time: 0 seconds")
        else:
            start_time = time.time()
            blocks = Utils.preprocess_data_input(ciphertext)
            plain_blocks = []
            for block in blocks:
                tmp = Utils.decrypt(block, key)
                plain_blocks.append(tmp)
            plain_blocks = [Utils.to_ascii(i) for i in plain_blocks]
            plaintext = "".join(plain_blocks).replace("\x00", "")
            end_time = time.time()
            self.plaintext_edit2.setText(plaintext)
            self.take_time2.setText(f"Take time: {round(end_time - start_time, 4)} seconds")

    def import_cipher_text_file(self):
        # Code cho chức năng Import file
        file_name, _ = QFileDialog.getOpenFileName(self, "Open File", "", "Text Files (*.txt)")
        if file_name:
            with open(file_name, "r") as f:
                self.cipher_text_edit2.setText(f.read())

    def import_plain_text_file(self):
        # Code cho chức năng Import file
        file_name, _ = QFileDialog.getOpenFileName(self, "Open File", "", "Text Files (*.txt)")
        if file_name:
            with open(file_name, "r") as f:
                self.plain_text.setText(f.read())

    def export_plain_text_file(self):
        filename, _ = QFileDialog.getSaveFileName(self, 'Export File', '', 'Text Files (*.txt);;All Files (*)')
        if filename:
            # Ghi dữ liệu ra tệp tin
            with open(filename, 'w') as file:
                file.write(self.plaintext_edit2.toPlainText())

    def export_cipher_text_file(self):
        filename, _ = QFileDialog.getSaveFileName(self, 'Export File', '', 'Text Files (*.txt);;All Files (*)')

        if filename:
            # Ghi dữ liệu ra tệp tin
            with open(filename, 'w') as file:
                file.write(self.ciphertext_edit.toPlainText())

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = AESWindow()
    ex.show()
    sys.exit(app.exec())