import socket
import os
import sys
import struct
import time
import select
import binascii
from Crypto.Cipher import AES
from base64 import b64encode
from base64 import b64decode

# Para executar o script, use o comando:
# sudo python3 ICMP-Ping-Scan.py "chave"

ICMP_ECHO_REQUEST = 8

#Tamanhos da chave permitidas do AES: 16, 24 ou 32 bytes.
key = b'Chave secreta!!!'

#nonce e tag são obtidos na cifração da mensagem e são utilizados na decifração
nonce = 'foo'
tag = 'foo'

def receiveOnePing(mySocket,use_crypto):
  while 1:
    recPacket, addr = mySocket.recvfrom(1024)
    #Fill in start
    #Fetch the ICMP header from the IP packet
    icmph = recPacket[20:28]
    type, code, checksum, pID, sq = struct.unpack("bbHHh", icmph)

    print("O cabeçalho da resposta ICMP: ",type, code, checksum, pID, sq)

    print("ID do ICMP recebido: ", str(pID))

    print("Por favor, informe o ID do Ping a ser recebido: ")
    ID = input()
    if str(pID) != str(ID):
      continue

    bytesinDbl = struct.calcsize("d")
    bytesinUnsignedInt = struct.calcsize("I")

    start_pos_time = 28
    end_pos_time = start_pos_time + bytesinDbl

    #Recupera a mensagem escondida no ping
    start_pos_msg_size = end_pos_time
    end_pos_msg_size = start_pos_msg_size + bytesinUnsignedInt
    (i,), msg_cifrada = struct.unpack("I", recPacket[start_pos_msg_size: end_pos_msg_size]), recPacket[end_pos_msg_size: ]

    if use_crypto == True:
      print("Mensagem cifrada recebida: "+str(msg_cifrada))

      print("Por favor, informe o nonce: ")
      nonce = input()
      nonce = b64decode(nonce)
      print("Por favor, informe a tag: ")
      tag = input()
      tag = b64decode(tag)

      cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
      msg_decifrada = cipher.decrypt(msg_cifrada)
      try:
        cipher.verify(tag)
        print("Mensagem em claro:", msg_decifrada)
      except ValueError:
        print("Chave incorreta ou mensagem corrompida")
    else:
      msg_decifrada = msg_cifrada
      print("Mensagem em claro recebida: " + str(msg_decifrada))


def ping(use_crypto, arg_key, timeout=1):
  #Trata para que a chave tenha algum dos tamanhos permitidos 16, 24 ou 32
  if len(arg_key) < 16:
    arg_key = arg_key.ljust(16)
  elif len(arg_key) > 16 and len(arg_key) < 24:
    arg_key = arg_key.ljust(24)
  elif len(arg_key) > 24 and len(arg_key) < 32:
    arg_key = arg_key.ljust(32)
  elif len(arg_key) > 32:
    arg_key = arg_key[:32]

  global key
  key = bytes(arg_key, encoding = "utf-8")

  icmp = socket.getprotobyname("icmp")
  #SOCK_RAW is a powerful socket type. For more details:   http://sock-raw.org/papers/sock_raw

  # Cria o socket
  mySocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)

  delay = receiveOnePing(mySocket,use_crypto)
  mySocket.close()

if __name__ == '__main__':
  print("Parâmetros recebidos")
  print("Habilitou a criptografia (Y|N): " + str(sys.argv[1]))
  if str(sys.argv[1]) == 'Y':
    use_crypto = True
    print("Chave a ser utilizada na criptografia: " + str(sys.argv[2]))
    arg_key = str(sys.argv[2])
  else:
    use_crypto = False
    arg_key = 'foo'

  ping(use_crypto,arg_key)

