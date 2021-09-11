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

# Para executar o script, use o comando:
# sudo python3 ICMP-Ping_Dialog.py --Host "google.com" --Mensagem "msg a ser escondida" --Crypto "Y" --Key "chave da criptografia" --Nonce "nonce"

ICMP_ECHO_REQUEST = 8

#Tamanhos da chave permitidas do AES: 16, 24 ou 32 bytes.
key = b'Chave secreta!!!'

#nonce utilizado na criptografia
nonce = 'foo'

def checksum(str):
  csum = 0
  countTo = (len(str) / 2) * 2
  count = 0
  while count < countTo:
    thisVal = str[count+1] * 256 + str[count]
    csum = csum + thisVal
    csum = csum & 0xffffffff 
    count = count + 2

  if countTo < len(str):
    csum = csum + ord(str[len(str) - 1])
    csum = csum & 0xffffffff

  csum = (csum >> 16) + (csum & 0xffff)
  csum = csum + (csum >> 16)
  
  answer = ~csum
  answer = answer & 0xffff
  answer = answer >> 8 | (answer << 8 & 0xff00)

  return answer

def decifra(msg_cifrada):
  global key
  global nonce
  print("Mensagem cifrada recebida: " + str(msg_cifrada))


  try:
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    msg_decifrada = cipher.decrypt(msg_cifrada)
    print("A mensagem em claro: ", str(msg_decifrada))
  except:
    print("Chave incorreta ou mensagem corrompida")
    msg_decifrada = 'error'

  return msg_decifrada

def receiveOnePing(mySocket, ID, timeout, destAddr, use_crypto):
  timeLeft = timeout

  while 1:
    startedSelect = time.time()
    whatReady = select.select([mySocket], [], [], timeLeft)
    howLongInSelect = (time.time() - startedSelect)
    if whatReady[0] == []: # Timeout
      return "Request timed out."

    timeReceived = time.time()
    recPacket, addr = mySocket.recvfrom(1024)

    #Fill in start
    #Fetch the ICMP header from the IP packet
    icmph = recPacket[20:28]
    type, code, checksum, pID, sq = struct.unpack("bbHHh", icmph)

    print("O cabeçalho da resposta ICMP: ",type, code, checksum, pID, sq)
    print("ID do ICMP: " + str(ID))
    if pID == ID:
      bytesinDbl = struct.calcsize("d")
      bytesinUnsignedInt = struct.calcsize("I")

      start_pos_time = 28
      end_pos_time = start_pos_time + bytesinDbl
      timeSent = struct.unpack("d", recPacket[start_pos_time:end_pos_time])[0]
      rtt=timeReceived - timeSent

      #Recupera a mensagem escondida no ping
      start_pos_msg_size = end_pos_time
      end_pos_msg_size = start_pos_msg_size + bytesinUnsignedInt
      (i,), msg_cifrada = struct.unpack("I", recPacket[start_pos_msg_size: end_pos_msg_size]), recPacket[end_pos_msg_size: ]
      if use_crypto == True:
        msg_decifrada = decifra(msg_cifrada)
      else:
        msg_decifrada = msg_cifrada
        print("Mensagem em claro recebida: " + str(msg_decifrada))

      return rtt, msg_decifrada

    timeLeft = timeLeft - howLongInSelect
    if timeLeft <= 0:
      return "Request timed out."


def cifra(msg_bytes):
  global key
  global nonce
  cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
  msg_bytes = cipher.encrypt(msg_bytes)
  print("Mensagem cifrada enviada: " + str(msg_bytes))

  # Caso o tamanho da cifra seja ímpar adiciona um espaço em branco no final
  if (len(msg_bytes) % 2 == 1):
    msg_bytes = msg_bytes + bytes(" ", 'utf-8')

  return msg_bytes

def sendOnePing(mySocket, msg, destAddr, ID, use_crypto=False):
  # Header is type (8), code (8), checksum (16), id (16), sequence (16)
  myChecksum = 0
  header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)

  timeSent = time.time()
  data = struct.pack("d", timeSent)

  #Insere a mensagem escondida no ping
  msg_str = str(msg)
  msg_bytes = bytes(msg_str, 'utf-8')

  # Caso o tamanho da mensagem seja ímpar adiciona um espaço em branco no final
  if (len(msg_bytes) % 2 == 1):
    msg_bytes = msg_bytes + bytes(" ", 'utf-8')

  if use_crypto == True:
    msg_bytes = cifra(msg_bytes)

  data += struct.pack("I%ds" % (len(msg_bytes),), len(msg_bytes), msg_bytes)

  myChecksum = checksum(header + data)

  if sys.platform == 'darwin':
    myChecksum = socket.htons(myChecksum) & 0xffff
  else:
    myChecksum = socket.htons(myChecksum)

  print("O cabeçalho da requisição ICMP: ", ICMP_ECHO_REQUEST,0,myChecksum,ID,1)
  header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
  packet = header + data
  mySocket.sendto(packet, (destAddr, 1))


def doOnePing(destAddr, msg, timeout,use_crypto=False):
  icmp = socket.getprotobyname("icmp")
  mySocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
  myID = os.getpid() & 0xFFFF
  print("ID do ICMP: " + str(myID))
  sendOnePing(mySocket, msg, destAddr, myID,use_crypto)
  delay = receiveOnePing(mySocket, myID, timeout, destAddr,use_crypto)
  mySocket.close()
  return delay

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

def ping(host, msg, use_crypto, arg_key='foo', arg_nonce='foo', timeout=1):

  global key
  key = bytes(trata_tamanho_chave(arg_key), encoding = "utf-8")
  global nonce
  nonce = bytes(arg_nonce, encoding = "utf-8")

  try:
    dest = socket.gethostbyname(host)
    print("O domínio informado foi resolvido para o IP: " + dest)

    delay, msg = doOnePing(dest, msg, timeout,use_crypto)
    print("O RTT calculado: " + str(delay))
    print("Mensagem escondida recuperada no echo reply: " + str(msg))

  except Exception as e:
    delay = 0
    print(e)

  return delay

if __name__ == '__main__':

  parser = argparse.ArgumentParser(description='Script que realiza um Ping para a disciplina de redes')
  parser.add_argument('--Host', action="store", help='Domínio a ser pingado', required=True)
  parser.add_argument('--Mensagem', action="store", help='Mensagem a ser escondida no ping', required=True)
  parser.add_argument('--Crypto', action="store", help='Habilitou a criptografia (Y|N)', required=True)
  parser.add_argument('--Key', action="store", help='Chave a ser utilizada na criptografia', required=False)
  parser.add_argument('--Nonce', action="store", help='Nonce a ser utilizado na criptografia', required=False)

  given_args = vars(parser.parse_args())

  print("Parâmetros recebidos")
  arg_host = str(given_args["Host"])
  print("Destino a ser pingado: " + arg_host)
  arg_mensagem = str(given_args["Mensagem"])
  print("Mensagem a ser escondida no ping: " + arg_mensagem)
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

  ping(arg_host, arg_mensagem, use_crypto,arg_key,arg_nonce)