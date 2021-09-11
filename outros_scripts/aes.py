from Crypto.Cipher import AES

#Tamanhos da chave permitidas: 16, 24 ou 32 bytes.
key = b'Chave secreta!!!'
nonce = b'Nonce'

cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
data = b'Mensagem a ser criptografada'
print("A mensagem em claro: " + str(data))

ciphertext = cipher.encrypt(data)

print("A mensagem cifrada: " + str(ciphertext))

try:
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    print("A mensagem em claro: ", str(plaintext))
except:
    print("Incorrect decryption")
