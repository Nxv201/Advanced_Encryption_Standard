import Utils
import time

lua_chon = 0
plaintext = ''
ciphertext = ''
key = ''

while lua_chon != 1 and lua_chon != 2:
    lua_chon = int(input("Chọn chức năng (1 - Encrypt, 2 - Decrypt): "))
if lua_chon == 1:
    dir = input("Nhập vào tên file cần mã hóa: ")
    while True:
        try:
            with open(dir) as file:
                plaintext = file.read()
        except:
            dir = input("File không tồn tại. Nhập lại: ")
        else:
            break
    key = input("Nhập khóa: ")
    start_time = time.time()
    blocks = Utils.preprocess_data_input(plaintext)
    cipher_blocks = []
    for block in blocks:
        tmp = Utils.encrypt(block, key)
        cipher_blocks.append(tmp)
    cipher_blocks = [Utils.to_ascii(i) for i in cipher_blocks]  # chuyen hex sang ki tu
    ciphertext = "".join(cipher_blocks)
    end_time = time.time()
    print("Kết quả: ", ciphertext)
    print(f'Thời gian: {round(end_time - start_time, 4)} s')
elif lua_chon == 2:
    dir = input("Nhập vào tên file cần giải mã hóa: ")
    while True:
        try:
            with open(dir) as file:
                ciphertext = file.read()
        except:
            dir = input("File không tồn tại. Nhập lại: ")
        else:
            break
    key = input("Nhập khóa: ")
    start_time = time.time()
    blocks = Utils.preprocess_data_input(ciphertext)
    plain_blocks = []
    for block in blocks:
        tmp = Utils.decrypt(block, key)
        plain_blocks.append(tmp)
    plain_blocks = [Utils.to_ascii(i) for i in plain_blocks]  # chuyen hex sang ki tu
    plaintext = "".join(plain_blocks).replace("\x00", "")
    end_time = time.time()
    print("Kết quả: ", plaintext)
    print(f'Thời gian: {round(end_time - start_time, 4)} s')
