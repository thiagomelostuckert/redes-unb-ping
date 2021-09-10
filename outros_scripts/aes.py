from Crypto.Cipher import AES

#Tamanhos da chave permitidas: 16, 24 ou 32 bytes.
key = b'Chave secreta!!!'

cipher = AES.new(key, AES.MODE_EAX)
nonce = cipher.nonce
data = b'Mensagem a ser criptografada'
ciphertext, tag = cipher.encrypt_and_digest(data)

print(ciphertext)

cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
plaintext = cipher.decrypt(ciphertext)
try:
    cipher.verify(tag)
    print("The message is authentic:", plaintext)
except ValueError:
    print("Key incorrect or message corrupted")
