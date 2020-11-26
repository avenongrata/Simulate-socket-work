import os
import sys
import signal
from datetime import datetime
import threading

main_path = ''


def fun_encode_message(symbol):
	code = bin(ord(symbol))
	code = str(code)
	code = code[2:]
	if len(code) == 8:
		return code
	else:
		while len(code) != 8:
			code = '0' + code
		return code


def fun_encode_n_bytes_message(string, N_byte):
	#string = string[::-1]
	new_string = []
	count_of_symbols = 0
	count_of_sequence = 0
	sequence = []
	for x in string:
		new_string.append(x)
		count_of_symbols += 1
		if count_of_symbols == 8:
			count_of_sequence += 1
			if count_of_sequence == N_byte:
				new_string = ''.join(new_string)
				sequence.append(new_string) # new test later
				new_string = []
				count_of_symbols = 0
				count_of_sequence = 0
			else:
				count_of_symbols = 0

	#count_of_symbols = 0
	if count_of_sequence != 0:
		#string_of_zeros = []
		while True:
			new_string.append('0')
			count_of_symbols += 1
			if count_of_symbols == 8:
				count_of_sequence += 1
				if count_of_sequence == N_byte:
					new_string = ''.join(new_string) 
					sequence.append(new_string) # new test later
					return sequence
				else:
					#new_string = ''.join(new_string)
					#sequence.append(new_string)
					count_of_symbols = 0
					#new_string = []			
	else: 
		return sequence


def fun_make_heads_coded(string):
	coded_string = []
	for symbol in string:
		coded_symbol = fun_encode_message(symbol)
		coded_string.append(coded_symbol)
	coded_string = ''.join(coded_string)
	return coded_string



def fun_sort_files(list_of_files):
	files_to_int = []
	sorted_files = []
	for filename in list_of_files:
		files_to_int.append(int(filename))
	files_to_int.sort()
	for file_name_int in files_to_int:
		sorted_files.append(str(file_name_int))
	return sorted_files



def fun_make_8bit_strings(bit_string):
	strings_8bit = []
	one_8bit_string = []
	count_of_symbols = 0
	for bit in bit_string:
		one_8bit_string.append(bit)
		count_of_symbols += 1
		if count_of_symbols == 8:
			one_8bit_string = ''.join(one_8bit_string)
			strings_8bit.append(one_8bit_string)
			one_8bit_string = []
			count_of_symbols = 0
	return strings_8bit



def fun_make_string(bit_string):
	list_of_bit_strings = fun_make_8bit_strings(bit_string)
	string = []
	for bit_string in list_of_bit_strings:
		string.append(chr(int('0b' + bit_string, 2)))
	string = ''.join(string)
	return string


def fun_findout_last_bit(bit_string):
	bit_string = bit_string[::-1]
	for bit in bit_string:
		if bit == '1' or bit == '0':
			break
		else:
			bit_string = bit_string[1:]
	return bit_string[::-1]



def signal_handler(sig, frame):
	print(signal_handler.__name__)
	thread_1 = threading.Thread(target = fun_thread)
	thread_1.start()



def fun_thread():
	again_testing = Level1()
	Level5.recv(again_testing, Level4.recv(again_testing, Level3.recv(again_testing, Level2.recv(again_testing, Level1.recv(again_testing)))))
	print("Input the message, if wanna stop - exit: ")


class Level5:
	def send(self, string):
		self.string = string
		receivers = []
		receiver_x = []
		message = []
		sender_of_the_message = 'host1' # sender of message = name of the file without '.py'
		for symbol in self.string:
			if symbol == ' ':
				receiver_x = ''.join(receiver_x)
				receivers.append(receiver_x)
				receiver_x = []
				continue
			if symbol == ':':
				pos = self.string.find(':')
				self.string = self.string[pos + 2:]
				for symbol_message in self.string:
					message.append(symbol_message)
				message = ''.join(message)
				break
			receiver_x.append(symbol)

		string_for_next_level = sender_of_the_message + '\n'
		for receiver in receivers:
			string_for_next_level += receiver
			string_for_next_level += '\n'
		string_for_next_level = string_for_next_level + "\r\n" + message + '\n'
		print("Level5-info:\nreceivers: {0} , message: {1}\n".format(receivers, message))
		print("Level5 fnl:\n{0}".format(string_for_next_level)) # fnl = for next level
		return string_for_next_level


	def recv(self, string):
		self.string = string
		strings = self.string.split('\n')
		sender_of_the_message = strings[2]
		message = strings[-2]
		# find sender of the message in the file
		os.chdir(main_path)
		with open('hosts', 'r') as file:
			for line in file:
				pos = line.find(sender_of_the_message)
				if pos != -1:
					strings = line.split(' ')
					sender_of_the_message = strings[0]
					break	
		end_message = sender_of_the_message + ' : ' + message
		print("Level5 fnl:\n{0}".format(end_message))		



class Level4(Level5):
	count_of_messages = 0 # counter of messages
	def send(self, string):
		self.string = string
		# add time & date
		time_of_msg = str(datetime.now()) + '\n'
		string_for_next_level = time_of_msg + self.string
		# find len of the message
		pos = self.string.find('\r\n')
		pos += 2
		msg_from_level5 = self.string[pos:-1]
		len_of_the_message = str(len(msg_from_level5)) + '\n'
		string_for_next_level = len_of_the_message + string_for_next_level
		# add count of message
		string_for_next_level = str(Level4.count_of_messages) + '\n' + string_for_next_level
		Level4.count_of_messages += 1
		#print("Level4-info:\n{0}".format(self.string))
		print("Level4 fnl:\n{0}".format(string_for_next_level))
		return string_for_next_level 


	def recv(self, strings):
		self.strings = strings
		string_for_next_level = []
		message = []
		for string in self.strings:
			string = string.split('\n')
			message.append(string[6])
		message = ''.join(message) + '\n'
		string = self.strings[0].split('\n')
		string = string[0] + '\n' + string[2] + '\n' + string[3] + '\n' + string[4] + '\n' + string[5] + '\n'
		string_for_next_level = string + message
		print("Level4 fnl:\n{0}".format(string_for_next_level))
		return string_for_next_level



class Level3(Level4):
	def send(self, string):
		self.string = string
		N_byte = 10 # you can change this number
		type_of_coding = 'ASCII'
		count_of_packets = 0 # it's counter for sender packets
		# find out the name of sender
		count_of_next_string = 0
		count_of_symbols = 0
		sender_of_the_message = []
		for symbol in self.string:
			if count_of_next_string == 3:
				string = self.string[count_of_symbols:]
				for symbol in string:
					if symbol == '\n':
						break
					sender_of_the_message.append(symbol)
				break
			if symbol == '\n':
				count_of_next_string += 1
			count_of_symbols += 1
		sender_of_the_message = ''.join(sender_of_the_message)					
		# find out the host of sender
		host_sender = []
		host_sender_x = []
		os.chdir(main_path)
		with open('hosts', 'r') as file:
			for line in file:
				pos = line.find(sender_of_the_message)
				if pos == -1:
					continue
				else:
					pos = pos + len(sender_of_the_message) + 1 # host1 host-host1 (in file)
					line = line[pos:]
					for symbol in line:
						if symbol == '\n':
							host_sender_x = ''.join(host_sender_x)
							host_sender.append(host_sender_x)
							host_sender_x = []
							break
						host_sender_x.append(symbol)
		host_of_sender = ''.join(host_sender)
		# find the message 
		pos = self.string.find('\r\n')
		pos += 2
		msg_from_level5 = self.string[pos:-1]
		# make string of coded symbols
		coded_symbol_list = []
		for symbol in msg_from_level5:
			coded_symbol = fun_encode_message(symbol)
			coded_symbol_list.append(coded_symbol)
		string_of_coded_symbols = ''.join(coded_symbol_list)
		# make N_byte sequences
		sequences = fun_encode_n_bytes_message(string_of_coded_symbols, N_byte)
		# make len of sequence
		len_of_sequence = str(len(sequences[0]) // 8)
		# find the receivers
		count_of_next_string = 0
		receivers = []
		receiver_x = []
		count_of_symbols = 0
		for symbol in self.string:
			if count_of_next_string == 4:
				string_with_receivers = self.string[count_of_symbols:]
				for symbol in string_with_receivers:
					if symbol == '\r':
						break
					if symbol == '\n':
						receiver_x = ''.join(receiver_x)
						receivers.append(receiver_x)
						receiver_x = []
						continue
					receiver_x.append(symbol)
				break				
			if symbol == '\n':
				count_of_next_string += 1
			count_of_symbols += 1
		# find out hosts of receivers
		# for that will pars file - hosts
		# path of file hosts is - main_path = '/home/stik/Desktop/Sispi_PZ4'
		host_receivers = []
		host_receiver_x = []
		os.chdir(main_path)
		with open('hosts', 'r') as file:
			for line in file:
				for receiver in receivers:
					pos = line.find(receiver)
					if pos == -1:
						continue
					else:
						pos = pos + len(receiver) + 1 # host2 host-host2 (in file)
						line = line[pos:]
						for symbol in line:
							if symbol == '\n':
								host_receiver_x = ''.join(host_receiver_x)
								host_receivers.append(host_receiver_x)
								host_receiver_x = []
								break
							host_receiver_x.append(symbol)
		# make packets for next level
		packets = []
		for sequence in sequences:
			heads = str(count_of_packets) + '\n' # add ID of packet
			count_of_packets += 1
			for host in host_receivers: # add hosts of receivers 
				heads = heads + host + ','
			heads = heads[:-1]
			heads += '\n' # end of list of hosts of receivers
			heads = heads + host_of_sender + '\n' # add host of sender
			heads = heads + type_of_coding + '\n' # add type of coding
			heads = heads + len_of_sequence + '\n' # add len of sequence
			heads_coded = fun_make_heads_coded(heads) # make bit string of heads
			packet = heads_coded + sequence + fun_encode_message('\n') # after sequence must be '\n'
			packets.append(packet)
		#print("Level3-info:\n{0}".format(self.string))
		packet_counter = 0
		for packet in packets:
			print("Level3 fnl[{0}]:\n{1}".format(packet_counter, packet))
			packet_counter += 1
		return packets

	def recv(self, packets):
		self.packets = packets
		msg_with_heads = []
		for packet in packets:
			string = fun_make_string(packet)
			msg_with_heads.append(string)
		#msg_with_heads = ''.join(msg_with_heads)
		#print(msg_with_heads)  #####
		pretty_strings = []
		for string in msg_with_heads:
			pos = string.find('\x00')
			if pos != -1:
				string = string[:pos]
				string += '\n'
				pretty_strings.append(string)
				continue
			pretty_strings.append(string)
		#packet_counter = 0
		#for packet in self.packets:
		#	print("Level3-info[{0}]:\n{1}".format(packet_counter, packet))
		#	packet_counter += 1
		packet_counter = 0
		print()
		for string in pretty_strings:
			print("Level3 fnl[{0}]:\n{1}".format(packet_counter, string))
			packet_counter += 1
		return pretty_strings


class Level2(Level3):
	def send(self, packets):
		self.packets = packets
		type_of_special_coding = 'parity bit'
		packets_for_next_level = []
		for packet in self.packets:
			coded_head = fun_make_heads_coded(type_of_special_coding + '\n')
			packet = coded_head + packet
			if packet.count('1') % 2 != 0:
				packet += '1'
			else:
				packet += '0'
			packets_for_next_level.append(packet)
		#packet_counter = 0
		#for packet in self.packets:
		#	print("Level2-info[{0}]:\n{1}".format(packet_counter, packet))
		#	packet_counter += 1
		packet_counter = 0
		print()
		for packet in packets_for_next_level:
			print("Level2 fnl[{0}]:\n{1}".format(packet_counter, packet))
			packet_counter += 1
		return packets_for_next_level


	def recv(self, packets):
		self.packets = packets
		symbols_new_str = '00001010'
		packet_counter = 0
		print("\nLevel2 fnl:")
		for packet in self.packets:
			packet = fun_findout_last_bit(packet)
			parity_bit = packet[-1]
			packet = packet[:-1]
			if packet.count('1') % 2 != 0:
				if parity_bit == '1':
					print("Packet[{0}] was not changed".format(packet_counter))
					packet_counter += 1
				else:
					print("Packet[{0}] was changed".format(packet_counter))
					packet_counter += 1			
			else:
				if parity_bit == '0':
					print("Packet[{0}] was not changed".format(packet_counter))
					packet_counter += 1
				else:
					print("Packet[{0}] was changed".format(packet_counter))
					packet_counter += 1	
		#pos = self.packets[0].find(symbols_new_str) # find the type of special coding
		#type_of_special_coding = self.packets[0][:pos]
		#type_of_special_coding = fun_make_string(type_of_special_coding)
		#packet_counter = 0
		#for packet in self.packets:
		#	print("Level2 fnl[{0}]:\n{1}".format(packet_counter, packet))
		#	packet_counter += 1
		#packets_for_next_level = [] 
		#packet_counter = 0
		#for packet in self.packets:
		#	packet = packet[pos + len(symbols_new_str):]
		#	packets_for_next_level.append(packet)
		#	print("Level2-fnl[{0}]:\n{1} {2}".format(packet_counter, type_of_special_coding, packet))
		#	packet_counter += 1
		#return packets_for_next_level
		return self.packets




class Level1(Level2):
	def send(self, packets):
		self.packets = packets
		packet_counter = 0
		# main_path = '/home/stik/Desktop/Sispi_PZ4'
		os.chdir(main_path + '/host1/output') # change for other host
		print("\nLevel1 fnl:")
		for packet in self.packets:
			name_of_file = str(packet_counter)
			with open(name_of_file, 'w') as file:
				file.write(packet)
			print("Packet[{0}] saved in /host1/output".format(packet_counter)) # change for other host
			packet_counter += 1
		# send signal to env.py, that all packets are ready for sending
		os.kill(env, signal.SIGINT)
		# env.py will delete files from /output


	def recv(self):
		packets = []
		# go to incoming messages
		#os.chdir(main_path + '/host1/input') # change for other host
		for path, dirnames, filenames in os.walk(main_path + '/host1/input'):
			break
		filenames = fun_sort_files(filenames) 
		for filename in filenames:
			with open(path + '/' + filename, "r") as file:
				packet = file.read()
			packets.append(packet)
			os.remove(path + '/' + filename) # delete the file
		packet_counter = 0
		print()
		for packet in packets:
			print("Level1-info[{0}]:\n{1}".format(packet_counter, packet))
			packet_counter += 1		
		return packets



print("Pid of host1:", os.getpid())
print("Input the pid of the env: ", end = '')
env = int(input())
signal.signal(signal.SIGINT, signal_handler)


while True:
	print("Input the message, if wanna stop - exit: ")
	line = str(input())
	if line == 'exit':
		print("File connection refused")
		#os.kill(pid_of_other_host, signal.SIGKILL)
		break
	testing = Level5()
	Level1.send(testing, Level2.send(testing, Level3.send(testing, Level4.send(testing, Level5.send(testing, line)))))

	
#testing = Level5()
#Level5.send(testing, "host2 : message")
#Level4.send(testing, Level5.send(testing, "host2 : message"))
#Level3.send(testing, Level4.send(testing, Level5.send(testing, "host2 : message")))
#Level2.send(testing, Level3.send(testing, Level4.send(testing, Level5.send(testing, "host2 : message"))))
#Level1.send(testing, Level2.send(testing, Level3.send(testing, Level4.send(testing, Level5.send(testing, "host2 : message")))))


#again_testing = Level1()
#Level1.recv(again_testing)
#Level2.recv(again_testing, Level1.recv(again_testing))
#Level3.recv(again_testing, Level2.recv(again_testing, Level1.recv(again_testing)))
#Level4.recv(again_testing, Level3.recv(again_testing, Level2.recv(again_testing, Level1.recv(again_testing))))
#Level5.recv(again_testing, Level4.recv(again_testing, Level3.recv(again_testing, Level2.recv(again_testing, Level1.recv(again_testing)))))