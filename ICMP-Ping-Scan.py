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
import argparse
from crypto import trata_tamanho_chave,cifra,decifra

# Para executar o script, use o comando:
# sudo python3 ICMP-Ping-Scan.py  --Crypto "Y" --Key "chave" --Nonce "nonce"

ICMP_ECHO_REQUEST = 8

def receiveOnePing(mySocket,use_crypto, key,nonce):
  while 1:
    recPacket, addr = mySocket.recvfrom(1024)
    #Fill in start
    #Fetch the ICMP header from the IP packet
    icmph = recPacket[20:28]
    type, code, checksum, pID, sq = struct.unpack("bbHHh", icmph)

    print("O cabeçalho da resposta ICMP: ",type, code, checksum, pID, sq)

    print("ID do ICMP recebido: ", str(pID))

    opcao = input("Por favor, informe se é esse Ping que vc deseja decifrar (\"S\"/\"N\"): ")
    if opcao != "S":
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
      msg_decifrada = decifra(msg_cifrada,key,nonce)
    else:
      msg_decifrada = msg_cifrada
      print("Mensagem em claro recebida: " + str(msg_decifrada))

def ping(use_crypto, arg_key, arg_nonce, timeout=1):
  key = bytes(trata_tamanho_chave(arg_key), encoding="utf-8")
  nonce = bytes(arg_nonce, encoding="utf-8")

  icmp = socket.getprotobyname("icmp")
  #SOCK_RAW is a powerful socket type. For more details:   http://sock-raw.org/papers/sock_raw

  # Cria o socket
  mySocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)

  delay = receiveOnePing(mySocket,use_crypto,key,nonce)
  mySocket.close()

if __name__ == '__main__':

  parser = argparse.ArgumentParser(description='Script que realiza um Ping para a disciplina de redes')
  parser.add_argument('--Crypto', action="store", help='Habilitou a criptografia (Y|N)', required=True)
  parser.add_argument('--Key', action="store", help='Chave a ser utilizada na criptografia', required=False)
  parser.add_argument('--Nonce', action="store", help='Nonce a ser utilizado na criptografia', required=False)

  given_args = vars(parser.parse_args())

  print("Parâmetros recebidos")
  cryptoEnableArg = str(given_args["Crypto"])
  print("Habilitou a criptografia (Y|N): " + cryptoEnableArg)
  if cryptoEnableArg == 'Y':
    use_crypto = True
    arg_key = str(given_args["Key"])
    print("Chave a ser utilizada na criptografia: " + arg_key)
    arg_nonce = str(given_args["Nonce"])
    print("Nonce a ser utilizado na criptografia: " + arg_nonce)
  else:
    use_crypto = False
    arg_key = 'foo'
    arg_nonce= 'foo'

  ping(use_crypto,arg_key,arg_nonce)

