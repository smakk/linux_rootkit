import socket
import commands

def main():
	s = socket.socket()
	s.bind(("127.0.0.1", 8888))
	s.listen(512)
	while True:
		try:
			print("wait for connect")
			c,addr = s.accept()
			print("get connect\n")
			while 1:
				command = raw_input("$ ")
				c.sendall(command)
				if(command == "exit"):
					s.close()
					break
				data = c.recv(1024*1024)
				print(data)
		except:
			s.close()

if __name__ == "__main__":
	main()
