from Container import *
from DataParser import *
import socket
import sys

events = ['instructions,bus-cycles,branch-instructions,branch-misses,cache-misses,cache-references,node-loads,node-stores',
		'L1-dcache-load-misses,L1-dcache-loads,L1-dcache-stores,L1-icache-load-misses,LLC-load-misses,LLC-loads,branch-loads,iTLB-load-misses']

troj_dir = "/home/ubuntu/malware_seperated/trojan/"
virus_dir = "/home/ubuntu/malware_seperated/virus/"
backdoor_dir = "/home/ubuntu/malware_seperated/backdoor/"
rootkit_dir = "/home/ubuntu/malware_seperated/rootkit/"
worm_dir = "/home/ubuntu/malware_seperated/worm/"
mibench_dir = "/home/research/work/mibench/scripts/"
spec_dir = "/home/research/work/spec/scripts/"

#########################
file_list = 'worm_list'
file_dir = worm_dir
#########################

########## ASLRay Configuration ##########
# Set aslray_mode to True to run ASLRay exploits with HPC data collection
aslray_mode = False
aslray_binary = "/tmp/test"    # path to vulnerable binary inside the container
aslray_buffer = 1024           # buffer size for ASLRay exploit
aslray_shellcode = None        # optional custom shellcode (e.g. '\x31\x80...')
aslray_timeout = 60            # seconds before killing the exploit loop
##############################################

def is_net_on():
	try:
		host = socket.gethostbyname('www.google.com')
		s = socket.create_connection((host, 80), 2)
		return True
	except Exception:
		return False


if __name__ == "__main__":

	if is_net_on():
		print("****************************")
		print("Warning : Turn off the Internet!!")
		print("****************************")
		print("exiting...")
		sys.exit()

	cobj = Container()
	cont = cobj.get()

	if aslray_mode:
		# ASLRay exploit mode - run ASLRay inside containers with perf monitoring
		print("=== ASLRay Mode ===")
		print("binary: %s  buffer: %d  timeout: %ds" % (
			aslray_binary, aslray_buffer, aslray_timeout))

		# get list of samples to use as exploit targets
		fd = open('conf/%s'%(file_list), 'r')
		l_malware = fd.read().split('\n')
		fd.close()

		for num, name in enumerate(l_malware):
			print("%d -> %s (ASLRay)" %(num, name))
			clone = cobj.clone(cont)

			cobj.cmd_aslray(clone, "%s%s" % (file_dir, name),
				aslray_buffer, events[1],
				shellcode=aslray_shellcode,
				timeout=aslray_timeout)
			clone.destroy()

			p = Parser()
			p.parse(num)
	else:
		# Original mode - run malware samples directly with perf monitoring
		fd = open('conf/%s'%(file_list), 'r')
		l_malware = fd.read().split('\n')
		fd.close()

		for num, name in enumerate(l_malware):
			print("%d -> %s" %(num, name))
			clone = cobj.clone(cont)

			cobj.cmd(clone, "chmod 777 %s%s" % (file_dir, name))
			cobj.cmd(clone, "timeout 6s perf stat -I 10 -e %s -x, %s%s" % (events[1], file_dir, name))

			# For SPEC benchmarks
			#cobj.cmd(clone, "perf stat -I 10 -e %s -x, runspec --size=test --noreportable --tune=base --iterations=1 %s" % (events[1], name))
			#cobj.cmd(clone, 'runspec')
			clone.destroy()

			p = Parser()
			p.parse(num)
			#p.parse(name.replace(".","_"))
			#break
