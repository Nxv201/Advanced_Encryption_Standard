import numpy as np


Sbox = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

InvSbox = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)

Rcon = (0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)


def text2bytearray(text):
    """
    Hàm chuyển string thành một byte array
    :param text: string
    :return: byte array
    """

    tmp = text.split("0x")
    if tmp[0] == "":
        tmp = tmp[1]
    else:
        tmp = tmp[0]
    len_tmp = len(tmp)//2
    tmp = tmp.encode('UTF-8')
    tmp = int(tmp, 16)  # Chuyển chuỗi thành int
    array = [(tmp >> 8 * (len_tmp - 1 - i)) & 0xff for i in range(len_tmp)]
    return array


def sub_word(word):
    """
    Thay thế các byte trong từ 4-byte input word bằng các byte tương ứng trong S-box.

    :param word: array gồm 4 phần tử mỗi phần tử biểu diên 1-byte.

    :return: array mới sau khi thay thế
    """
    return np.asarray([Sbox[b] for b in word])


def sub_bytes(state_matrix):
    """
    Thay thế các byte trong state_matrix bằng các byte tương ứng trong S-box.
    :param state_matrix: ma trận trạng thái 4x4
    :return: ma trận trạng thái sau khi thay thế
    """
    matrix = np.copy(state_matrix)
    for i in range(4):
        for j in range(4):
            matrix[i][j] = Sbox[matrix[i][j]]
    return matrix


def rot_word(word):
    """
    Dịch trái 1 byte
    :param word: array
    :return: array
    """
    return np.roll(word, -1)


def key_expansion(master_key):
    """
    Hàm mở rộng khóa
    :param key: là một chuỗi hex. VD: '0x0f1571c947d9e8590cb7add6af7f6798'
    :return: danh sách các từ khóa
    """
    key = text2bytearray(master_key)

    # khai báo các thông số cần thiết
    Nk = len(key) // 4
    # print("len key: ", Nk)
    Nb = 4
    Nr = Nk + 6     # số lần lặp

    # khởi tạo khóa con đầu tiên bằng khóa chính
    w = [0] * (Nb * (Nr + 1))  # Khởi tạo một mảng để lưu key mở rộng
    arr = np.reshape(key, (Nk, 4))
    for i in range(Nk):
        w[i] = arr[i]


    # sinh khóa con
    for i in range(Nk, Nb * (Nr + 1)):
        temp = w[i - 1]
        if i % Nk == 0:
            temp = rot_word(temp)   # Rot_word
            temp = sub_word(temp)   # Sub_word
            temp = temp ^ [Rcon[i // Nk], 00, 00, 00]     # XOR Rcon
        elif Nk > 6 and i % Nk == 4:
            temp = sub_word(temp)
        w[i] = w[i - Nk] ^ temp
    return Nr, w


def shift_rows(state_matrix):
    """
    Dịch chuyển các giá trị trong mỗi hàng của ma trận state sang trái theo cách xác định.
    :param state_matrix:
    :return:
    """
    matrix = np.copy(state_matrix)
    matrix = np.asmatrix(matrix)
    matrix = matrix.getT()  # lấy ma trận chuyển vị

    for i in range(4):
        tmp = matrix[i]
        tmp = np.asarray(tmp)
        tmp = np.roll(tmp, -i)
        matrix[i] = tmp
    return matrix.getT()  # vì ở trên ta chuyển vị nên phải chuyển vị một lần nữa



def mul2(num):
    kq = num << 1
    if kq >= 256:
        kq = kq ^ 0x11B
    kq = kq & 0xFF
    return kq


def mul3(num):
    kq = (num << 1) ^ num
    if kq >= (256 << 2):
        kq = kq ^ (0x11B << 2)
    if kq >= (256 << 1):
        kq = kq ^ (0x11B << 1)
    if kq >= 256:
        kq = kq ^ 0x11B
    kq = kq & 0xFF
    return kq


def mul9(num):
    kq = (num << 3) ^ num
    if kq >= (256 << 2):
        kq = kq ^ (0x11B << 2)
    if kq >= (256 << 1):
        kq = kq ^ (0x11B << 1)
    if kq >= 256:
        kq = kq ^ 0x11B
    kq = kq & 0xFF
    return kq


def mul11(num):
    kq = (num << 3) ^ (num << 1) ^ num
    if kq >= (256 << 2):
        kq = kq ^ (0x11B << 2)
    if kq >= (256 << 1):
        kq = kq ^ (0x11B << 1)
    if kq >= 256:
        kq = kq ^ 0x11B
    kq = kq & 0xFF
    return kq


def mul13(num):
    kq = (num << 3) ^ (num << 2) ^ num
    if kq >= (256 << 2):
        kq = kq ^ (0x11B << 2)
    if kq >= (256 << 1):
        kq = kq ^ (0x11B << 1)
    if kq >= 256:
        kq = kq ^ 0x11B
    kq = kq & 0xFF
    return kq


def mul14(num):
    kq = (num << 3) ^ (num << 2) ^ (num << 1)
    if kq >= (256 << 2):
        kq = kq ^ (0x11B << 2)
    if kq >= (256 << 1):
        kq = kq ^ (0x11B << 1)
    if kq >= 256:
        kq = kq ^ 0x11B
    kq = kq & 0xFF
    return kq


def gmul(a, b):
    """
    nhân hai số trong trường GF(2^8)
    """
    if a == 2:
        kq = mul2(b)
    elif a == 3:
        kq = mul3(b)
    elif a == 9:
        kq = mul9(b)
    elif a == 11:
        kq = mul11(b)
    elif a == 13:
        kq = mul13(b)
    elif a == 14:
        kq = mul14(b)
    else:
        kq = b
    return kq


def mul_matrix(row, col):
    """
    Hàm nhân ma trận trong trường GF(2^8)
    :param row: hàng của ma trận cố định
    :param col: cột của ma trận trạng thái
    :return: giá trị của phần tử tại vị trí (row, col)
    """
    row = row.tolist()  # chuyển đổi hàng thành một danh sách (mảng 1 chiều)
    col = col.reshape(1, 4).tolist()[0]  # chuyển đổi cột thành một danh sách (mảng 1 chiều)
    result = 0
    for i in range(4):
        result ^= gmul(row[i], col[i])
    return result


def mix_columns(state_matrix):
    """
    Hàm mix_columns
    :param state_matrix: ma trận state
    :return: ma trận sau khi mix columns
    """
    # Hằng số cần thiết cho phép tính toán mix_columns
    mix_columns_const = np.array([
        [0x02, 0x03, 0x01, 0x01],
        [0x01, 0x02, 0x03, 0x01],
        [0x01, 0x01, 0x02, 0x03],
        [0x03, 0x01, 0x01, 0x02]
    ], dtype=np.uint8)
    state_matrix = state_matrix.getT()
    result = np.zeros_like(state_matrix, dtype=np.uint8)
    for i in range(4):
        for j in range(4):
            result[i, j] = mul_matrix(mix_columns_const[i, :], state_matrix[:, j])

    return result.getT()


def add_round_key(state_matrix, key_matrix):
    """
    XOR state với key
    :param state_matrix: là một ma trận 4x4
    :param key_matrix: là một ma trận 4x4
    :return: một trận 4x4
    """
    return state_matrix ^ key_matrix


def inv_shift_rows(state_matrix):
    """
    Dịch chuyển các giá trị trong mỗi hàng của ma trận state sang phải theo cách xác định.
    :param state_matrix: ma trận state
    :return: ma trận sau khi shift row
    """
    matrix = np.copy(state_matrix)
    matrix = np.asmatrix(matrix)
    matrix = matrix.getT()  # lấy ma trận chuyển vị

    for i in range(4):
        tmp = matrix[i]
        tmp = np.asarray(tmp)
        tmp = np.roll(tmp, i)  # dịch sang phải
        matrix[i] = tmp
    return matrix.getT()  # vì ở trên ta chuyển vị nên phải chuyển vị một lần nữa


def inv_sub_bytes(state_matrix):
    """
    Thay thế các byte trong state_matrix bằng các byte tương ứng trong invert S-box.
    :param state_matrix: ma trận trạng thái 4x4
    :return: ma trận trạng thái sau khi thay thế
    """
    matrix = np.copy(state_matrix)
    for i in range(4):
        for j in range(4):
            matrix[i][j] = InvSbox[matrix[i][j]]
    return matrix


def inv_mix_columns(state_matrix):
    """
    Hàm invert mix_columns
    :param state_matrix: ma trận state
    :return: ma trận sau khi mix columns
    """
    # Hằng số cần thiết cho phép tính toán mix_columns
    inv_mix_columns_const = np.array([
        [0x0e, 0x0b, 0x0d, 0x09],
        [0x09, 0x0e, 0x0b, 0x0d],
        [0x0d, 0x09, 0x0e, 0x0b],
        [0x0b, 0x0d, 0x09, 0x0e]
    ], dtype=np.uint8)
    state_matrix = np.asmatrix(state_matrix)
    state_matrix = state_matrix.getT()
    result = np.zeros_like(state_matrix, dtype=np.uint8)
    for i in range(4):
        for j in range(4):
            result[i, j] = mul_matrix(inv_mix_columns_const[i, :], state_matrix[:, j])

    return result.getT()


def encrypt(plaintext, master_key):
    """
    Hàm mã hóa AES
    :param master_key: là mỗi chuỗi khóa 128bit, 192bit, hoặc 256bit
    :param plaintext: là một chuỗi 128bit
    :return: là một string đã mã hóa
    """

    # chuyển text thành byte array
    plaintext = text2bytearray(plaintext)

    # chuyển array thành matrix
    plain_state = np.reshape(plaintext, (4, 4))

    # Mở rộng khóa
    Nr, round_keys = key_expansion(master_key)

    # Round đầu tiên
    sub_key = round_keys[0:4]
    key_matrix = np.asarray(sub_key)       # ndarray (4 , 4)
    print("input: \n", plain_state.astype(np.uint8).tobytes().hex())
    state_matrix = add_round_key(plain_state, key_matrix)  # k0-k3

    print("R1: \n", state_matrix.astype(np.uint8).tobytes().hex())
    # Các round tiếp theo
    for i in range(1, Nr):
        # Lấy khóa con
        sub_key = round_keys[4 * i: 4 * (i + 1)]
        key_matrix = np.asarray(sub_key)    # ndarray (4 , 4)

        state_matrix = sub_bytes(state_matrix)      # sub bytes
        print(f"R{i} sub bytes: \n", state_matrix.astype(np.uint8).tobytes().hex())
        state_matrix = shift_rows(state_matrix)     # shift rows
        print(f"R{i} shift rows: \n", state_matrix.astype(np.uint8).tobytes().hex())
        state_matrix = mix_columns(state_matrix)    # mix columns
        print(f"R{i} mix cols: \n", state_matrix.astype(np.uint8).tobytes().hex())
        print(f"R{i} sub_key: \n", key_matrix.astype(np.uint8).tobytes().hex())
        state_matrix = add_round_key(state_matrix, key_matrix)  # add round key
        print(f"R{i} add round key: \n", state_matrix.astype(np.uint8).tobytes().hex())

    # Round cuối
    sub_key = round_keys[-4:]  # Lấy khóa con
    key_matrix = np.asarray(sub_key)
    print("Matrix_key: \n", key_matrix.astype(np.uint8).tobytes().hex())

    state_matrix = sub_bytes(state_matrix)
    state_matrix = shift_rows(state_matrix)
    state_matrix = add_round_key(state_matrix, key_matrix)
    return state_matrix.astype(np.uint8).tobytes().hex()


def decrypt(ciphertext, master_key):
    """
    Hàm giải mã AES
    :param master_key: là mỗi chuỗi khóa 128bit, 192bit, hoặc 256bit
    :param ciphertext: là một chuỗi 128bit
    :return: là một string đã giải mã
    """
    # chuyển text thành byte array
    ciphertext = text2bytearray(ciphertext)

    # chuyển array thành matrix
    cipher_state = np.reshape(ciphertext, (4, 4))

    # Mở rộng khóa
    Nr, round_keys = key_expansion(master_key)

    # Round đầu tiên
    sub_key = round_keys[-4:]
    key_matrix = np.asarray(sub_key)  # ndarray (4 , 4)
    print("input decrypt: \n", cipher_state.astype(np.uint8).tobytes().hex())
    state_matrix = add_round_key(cipher_state, key_matrix)

    # Các round tiếp theo
    for i in range(Nr-1, 0, -1):
        sub_key = round_keys[4 * i: 4 * (i + 1)]
        key_matrix = np.asarray(sub_key)  # ndarray (4 , 4)
        print("matrix_key: \n", key_matrix.astype(np.uint8).tobytes().hex())

        state_matrix = inv_shift_rows(state_matrix)             # invert shift rows
        print(f"R{i} invert shift rows: \n", state_matrix.astype(np.uint8).tobytes().hex())
        state_matrix = inv_sub_bytes(state_matrix)              # invert sub bytes
        print(f"R{i} invert sub bytes: \n", state_matrix.astype(np.uint8).tobytes().hex())
        state_matrix = add_round_key(state_matrix, key_matrix)  # add round key
        print(f"R{i} add round key: \n", state_matrix.astype(np.uint8).tobytes().hex())
        state_matrix = inv_mix_columns(state_matrix)            # invert mix columns
        print(f"R{i} invert mix cols: \n", state_matrix.astype(np.uint8).tobytes().hex())

    # Round cuối
    sub_key = round_keys[: 4]
    key_matrix = np.asarray(sub_key)
    state_matrix = inv_shift_rows(state_matrix)
    state_matrix = inv_sub_bytes(state_matrix)
    state_matrix = add_round_key(state_matrix, key_matrix)

    return state_matrix.astype(np.uint8).tobytes().hex()


# master_key = '0x2b7e151628aed2a6abf7158809cf4f3c'
# input = '0x3243f6a8885a308d313198a2e0370734'
# input = text2bytearray(input)
# input_matrix = np.reshape(input, (4, 4))  # ndarray (4 , 4) tương đương với 1 ma trân 4x4
# key = key_expansion(master_key)
# sub_key = key[0:4]
# key_matrix = np.asarray(sub_key)       # ndarray (4 , 4)
#
#
# #add round key
# state_matrix = add_round_key(input_matrix, key_matrix) # ma trận chưa chuyển vị tức là các từ khóa đang là các hàng
# #subbyte
# state_matrix = sub_bytes(state_matrix)
# #
# state_matrix = shift_rows(state_matrix)
# #
# state_matrix = mix_columns(state_matrix)
# print(state_matrix)
# master_key = '0x2b7e151628aed2a6abf7158809cf4f3c'
# input = '0x3243f6a8885a308d313198a2e0370734'
# state = encrypt(input, master_key)
# print(state.tobytes().hex())

if __name__ == "__main__":

    master_key = '0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
    PLAINTEXT = '0x00112233445566778899aabbccddeeff'
    state = encrypt(PLAINTEXT, master_key)
    # print(type(state))
    state = state.astype(np.uint8).tobytes().hex()
    print("encryt: ", state)
    state = decrypt(state, master_key)
    state = state.astype(np.uint8).tobytes().hex()
    print("decryt: ", state)
