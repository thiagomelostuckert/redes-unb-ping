import socket
import os
import sys
import struct
import time
import select
import argparse
from crypto import trata_tamanho_chave,cifra,decifra
import numpy as np

# Para executar o script, use o comando:
# sudo python3 ICMP-Ping_Dialog.py --Host "google.com" --Mensagem "msg a ser escondida" --Crypto "Y" --Key "chave" --Nonce "nonce" --Qtde 1

ICMP_ECHO_REQUEST = 8

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

def receiveOnePing(mySocket, ID, timeout, destAddr, use_crypto,key,nonce):
  timeLeft = timeout
  delay = 0
  received = False
  while 1:

    startedSelect = time.time()
    whatReady = select.select([mySocket], [], [], timeLeft)
    howLongInSelect = (time.time() - startedSelect)
    if whatReady[0] == []: # Timeout
      return delay, received

    timeReceived = time.time()
    recPacket, addr = mySocket.recvfrom(1024)
    icmph = recPacket[20:28]

    type, code, checksum, pID, icmp_seq = struct.unpack("bbHHh", icmph)

    if pID == ID:
      received = True
      bytesinDbl = struct.calcsize("d")
      bytesinUnsignedInt = struct.calcsize("I")

      start_pos_time = 28
      end_pos_time = start_pos_time + bytesinDbl
      timeSent = struct.unpack("d", recPacket[start_pos_time:end_pos_time])[0]
      delay=timeReceived - timeSent

      #Recupera a mensagem escondida no ping
      start_pos_msg_size = end_pos_time
      end_pos_msg_size = start_pos_msg_size + bytesinUnsignedInt
      (i,), msg_cifrada = struct.unpack("I", recPacket[start_pos_msg_size: end_pos_msg_size]), recPacket[end_pos_msg_size: ]
      if use_crypto == True:
        msg_decifrada = decifra(msg_cifrada,key,nonce)
      else:
        msg_decifrada = msg_cifrada

      size_packet = len(recPacket)
      host = addr[0]

      ipHeader = struct.unpack('!BBHHHBBH4s4s', recPacket[0:20])
      ttl = ipHeader[5]
      delay = delay * 1000
      print("{} bytes from {}: icmp_seq={} ttl={} time={:.3f} ms".format(size_packet,host,icmp_seq,ttl, delay))

      return delay, received

    timeLeft = timeLeft - howLongInSelect
    if timeLeft <= 0:
      delay = 0
      received = False
      return delay, received

def sendOnePing(mySocket, msg, destAddr, ID, use_crypto,key,nonce):
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
    msg_bytes = cifra(msg_bytes,key,nonce)

  data += struct.pack("I%ds" % (len(msg_bytes),), len(msg_bytes), msg_bytes)

  myChecksum = checksum(header + data)

  if sys.platform == 'darwin':
    myChecksum = socket.htons(myChecksum) & 0xffff
  else:
    myChecksum = socket.htons(myChecksum)

  header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
  packet = header + data
  mySocket.sendto(packet, (destAddr, 1))


def doOnePing(destAddr, msg, timeout,use_crypto,key,nonce):
  icmp = socket.getprotobyname("icmp")
  mySocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
  myID = os.getpid() & 0xFFFF
  sendOnePing(mySocket, msg, destAddr, myID,use_crypto,key,nonce)
  delay,received = receiveOnePing(mySocket, myID, timeout, destAddr,use_crypto,key,nonce)
  mySocket.close()
  return delay,received

def ping(host, msg, use_crypto ,arg_key='foo', arg_nonce='foo', qtde_pings=3, timeout=1):
  key = bytes(trata_tamanho_chave(arg_key), encoding = "utf-8")
  nonce = bytes(arg_nonce, encoding = "utf-8")

  dest = socket.gethostbyname(host)
  if dest!=host:
    print("PING {} ({})".format(str(host),str(dest)))
  else:
    print("Ping {}".format(host))

  if msg != "":
    print("Mensagem a ser escondida: "+str(msg))

  delays =[]
  delay_min = 0
  delay_avg = 0
  delay_max = 0
  delay_stddev = 0

  packets_transmitted = 0
  packets_received = 0
  for i in range(0,qtde_pings):
    packets_transmitted += 1
    try:
      delay, received = doOnePing(dest, msg, timeout,use_crypto,key,nonce)
    except Exception as e:
      print(e)
      delay = 0
      received = False

    if (received == True):
      packets_received += 1
      delays.append(delay)

  if packets_received > 0:
    delay_min = np.min(delays)
    delay_avg = np.average(delays)
    delay_max = np.max(delays)
    delay_stddev = np.std(delays)

  print("--- {} ping statistics ---".format(host))
  packet_loss = float(packets_transmitted - packets_received) / float(packets_transmitted)
  packet_loss = packet_loss * 100
  print("{} packets transmitted, {} packets received, {:.2f}% packet loss".format(packets_transmitted, packets_received, packet_loss))
  print("round-trip min/avg/max/stddev = {:.3f}/{:.3f}/{:.3f}/{:.3f} ms".format(delay_min,delay_avg,delay_max,delay_stddev))


if __name__ == '__main__':

  parser = argparse.ArgumentParser(description='Script que realiza um Ping para a disciplina de redes')
  parser.add_argument('--Host', action="store", help='Domínio a ser pingado', required=True)
  parser.add_argument('--Mensagem', action="store", help='Mensagem a ser escondida no ping', required=False)
  parser.add_argument('--Crypto', action="store", help='Habilitou a criptografia (Y|N)', required=True)
  parser.add_argument('--Key', action="store", help='Chave a ser utilizada na criptografia', required=False)
  parser.add_argument('--Nonce', action="store", help='Nonce a ser utilizado na criptografia', required=False)
  parser.add_argument('--Qtde', action="store", help='Quantidade de pigns a ser enviado', required=False)

  given_args = vars(parser.parse_args())

  arg_host = str(given_args["Host"])

  if given_args["Mensagem"] is not None:
    arg_mensagem = str(given_args["Mensagem"])
  else:
    arg_mensagem = ""

  cryptoEnableArg = str(given_args["Crypto"])
  if cryptoEnableArg == 'Y':
    qtde_pings = 1
    use_crypto = True
    arg_key = str(given_args["Key"])
    arg_nonce = str(given_args["Nonce"])
  else:
    qtde_pings = 3
    use_crypto = False
    arg_key = 'foo'
    arg_nonce= 'foo'

  if given_args["Qtde"] is not None:
    qtde_pings = int(given_args["Qtde"])

  ping(arg_host, arg_mensagem, use_crypto,arg_key,arg_nonce, qtde_pings)