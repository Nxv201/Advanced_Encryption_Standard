from Utils import encrypt, decrypt
import time

key = '0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
plaintext = '0x00112233445566778899aabbccddeeff'

start_time = time.time()
state = encrypt(plaintext, key)
end_time = time.time()

print("encryt: ", state)
print(f'Time taken: {round(end_time - start_time, 4)} seconds')
start_time = time.time()
state = decrypt(state, key)
end_time = time.time()
print("decryt: ", state)
print(f'Time taken: {round(end_time - start_time, 4)} seconds')