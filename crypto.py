from Crypto.Cipher import AES

def decifra(msg_cifrada,key,nonce):
  #print("Mensagem cifrada recebida: " + str(msg_cifrada))
  try:
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    msg_decifrada = cipher.decrypt(msg_cifrada)
    #print("A mensagem em claro: ", str(msg_decifrada))
  except:
    #print("Chave incorreta ou mensagem corrompida")
    msg_decifrada = 'error'

  return msg_decifrada

def cifra(msg_bytes,key,nonce):
  cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
  msg_bytes = cipher.encrypt(msg_bytes)
  #print("Mensagem cifrada enviada: " + str(msg_bytes))

  # Caso o tamanho da cifra seja ímpar adiciona um espaço em branco no final
  if (len(msg_bytes) % 2 == 1):
    msg_bytes = msg_bytes + bytes(" ", 'utf-8')

  return msg_bytes

def trata_tamanho_chave(arg_key):
  # Trata para que a chave tenha algum dos tamanhos permitidos 16, 24 ou 32
  if len(arg_key) < 16:
    arg_key = arg_key.ljust(16)
  elif len(arg_key) > 16 and len(arg_key) < 24:
    arg_key = arg_key.ljust(24)
  elif len(arg_key) > 24 and len(arg_key) < 32:
    arg_key = arg_key.ljust(32)
  elif len(arg_key) > 32:
    arg_key = arg_key[:32]
  return arg_key
