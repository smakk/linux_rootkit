import socket
import commands

def main():
	s = socket.socket()
	s.bind(("127.0.0.1", 8889))
	s.listen(512)
	while True:
		try:
			c,addr = s.accept()
			print("get connect\n")
			while 1:
				print('''input format:\n
					exit: exit shell''')
				command = raw_input("$ ")
				c.sendall(command)
				print("send ok\n")
				if command == exit :
					break
				data = c.recv(1024*1024)
				print(data)
		except:
			s.close()
	print("Bye")

if __name__ == "__main__":
	main()
