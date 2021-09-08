import socket
import os
import sys
import struct
import time
import select
import binascii


# Para executar o script, use o comando: sudo python3 ICMP-Ping.py

ICMP_ECHO_REQUEST = 8

def checksum(str):
#  print("debug")
#  print(str)
  csum = 0
  countTo = (len(str) / 2) * 2
#  print(countTo)

  count = 0
  while count < countTo:
#    print(str[count])
#    print(str[count+1])
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


def receiveOnePing(mySocket, ID, timeout, destAddr):

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

    print("ICMP Header: ",type, code, checksum, pID, sq)
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
      (i,), msg = struct.unpack("I", recPacket[start_pos_msg_size: end_pos_msg_size]), recPacket[end_pos_msg_size: ]

      return rtt, msg


    # Fill in end

    timeLeft = timeLeft - howLongInSelect
    if timeLeft <= 0:
      return "Request timed out."

def sendOnePing(mySocket, msg, destAddr, ID):
  # Header is type (8), code (8), checksum (16), id (16), sequence (16)
  myChecksum = 0
  # Make a dummy header with a 0 checksum.
  # struct -- Interpret strings as packed binary data
  header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)

  timeSent = time.time()
  data = struct.pack("d", timeSent)

  #Insere a mensagem escondida no ping
  msg_str = str(msg)

  #Caso o tamanho da mensagem seja ímpar adiciona um espaço em branco no final
  if len(msg_str) % 2 == 1:
    msg_str+=" "

  msg_bytes = bytes(msg_str, 'utf-8')
  data += struct.pack("I%ds" % (len(msg_bytes),), len(msg_bytes), msg_bytes)

  # Calculate the checksum on the data and the dummy header.
  myChecksum = checksum(header + data)

  #Get the right checksum, and put in the header
  if sys.platform == 'darwin':
    myChecksum = socket.htons(myChecksum) & 0xffff   #Convert 16-bit integers from host to network byte order.
  else:
    myChecksum = socket.htons(myChecksum)

  print("ICMP Header: ", ICMP_ECHO_REQUEST,0,myChecksum,ID,1)
  header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
  packet = header + data

  mySocket.sendto(packet, (destAddr, 1))
  # AF_INET address must be tuple, not str.
  # Both LISTS and TUPLES consist of a number of objects
  # which can be referenced by their position number within the object.


def doOnePing(destAddr, msg, timeout):

  icmp = socket.getprotobyname("icmp")
  #SOCK_RAW is a powerful socket type. For more details:   http://sock-raw.org/papers/sock_raw

  # Fill in start
  # Create socket here.
  mySocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)

  # Fill in end
  myID = os.getpid() & 0xFFFF  #Return the current process i
  sendOnePing(mySocket, msg, destAddr, myID)
  delay = receiveOnePing(mySocket, myID, timeout, destAddr)
  mySocket.close()

  return delay


def ping(host, msg, timeout=1):
  #timeout=1 means: If one second goes by without a reply from the server,
  #the client assumes that either the client's ping or the server's pong is lost

  dest = socket.gethostbyname(host)
  print("Pinging " + dest + " using Python:")
  print("\n")

  # Send ping requests to a server separated by approximately one second.
  # I will be sending a single ping message to each server.
  print("The header fields for ICMP are: Type, Code, Checksum, ID, Sequence Number")
  delay,msg = doOnePing(dest, msg, timeout)
  print(delay)
  print("Mensagem escondida no ping: " + str(msg))
  time.sleep(1)# one second

  return delay

if __name__ == '__main__': 
	print(sys.argv[1], sys.argv[2])
	ping(sys.argv[1], sys.argv[2])

