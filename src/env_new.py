import shutil
import signal
import time
import os
import threading

main_path = '' # change only this string
host1_output =  main_path + 'host1/output/'
host1_input = main_path + 'host1/input/'
host2_output =  main_path + 'host2/output/'
host2_input = main_path + 'host2/input/'


def signal_handler(sig, frame):
	print(signal_handler.__name__)
	thread_1 = threading.Thread(target = fun_thread)
	thread_1.start()



def fun_thread():
	print(fun_thread.__name__)
	if fun_check_for_packets():
		print("Packets sended")
	else:
		print("Cant send Packets")



def fun_check_for_packets():
	# check host1/output
	flag_change_bit = 1
	for path, dirnames, filenames in os.walk(host1_output):
		break
	if len(filenames) != 0:
		for filename in filenames: # send and delete the files
			if flag_change_bit == 1:
				with open(path + '/' + filename, 'r') as file:
					buf = file.read()
					buf = list(buf)
					if buf[5] == '1':
						buf[5] = '0'
					else: 
						buf[5] = '1'
				buf = ''.join(buf)		
				with open(path + '/' + filename, 'w') as file:
					file.write(buf)
				flag_change_bit = 0
			shutil.move(host1_output + filename, host2_input + filename)
			#os.remove(path + '/' + filename) 
		os.kill(pid_of_host2, signal.SIGINT)
		return 1
	# check host2/output
	for path, dirnames, filenames in os.walk(host2_output):
		break
	if len(filenames) != 0:
		for filename in filenames: # send and delete the files
			if flag_change_bit == 1:
					with open(path + '/' + filename, 'r') as file:
						buf = file.read()
						buf = list(buf)
						if buf[5] == '1':
							buf[5] = '0'
						else: 
							buf[5] = '1'
					buf = ''.join(buf)		
					with open(path + '/' + filename, 'w') as file:
						file.write(buf)
					flag_change_bit = 0
			shutil.move(host2_output + filename, host1_input + filename)
			#os.remove(path + '/' + filename) 
		os.kill(pid_of_host1, signal.SIGINT)
		return 1
	return 0



print("Pid of env:", os.getpid())
print("Input the pid of the host1: ", end = '')
pid_of_host1 = int(input())
print("Input the pid of the host2: ", end = '')
pid_of_host2 = int(input())
signal.signal(signal.SIGINT, signal_handler)


while True:
	time.sleep(200)
	#pass
	

