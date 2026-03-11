import lxc
import os
import base64

# generic container class
class Container(object):

	def __init__(self):
		self.aslray_path = os.path.join(
			os.path.dirname(os.path.abspath(__file__)), 'ASLRay.sh')

	# get available container
	def get(self):
		cont = None
		for cont_obj in lxc.list_containers(as_object=True):
			if cont_obj.name == 'new-cont':
				cont = cont_obj

		assert cont.name == 'new-cont'

		return cont

	# clone container
	def clone(self, cont):
		print("cloning container for test...")

		clone = cont.clone('tmp-cont', flags=lxc.LXC_CLONE_SNAPSHOT)

		assert clone.name == 'tmp-cont'

		return clone

	# run command
	def cmd(self, cont, command):
		
		fd = open('output', 'w')
		fd_perf = open('perf_out', 'w')

		print("starting container..")
		cont.start()

		cont.attach_wait(lxc.attach_run_command, command.split(' '),
			stdout=fd, stderr=fd_perf)

		fd.close()
		fd_perf.close()
		
		print("stopping container..")
		cont.stop()

	# copy a file into a running container using base64 encoding
	def push_file(self, cont, src_path, dest_path):
		with open(src_path, 'rb') as f:
			content = f.read()
		encoded = base64.b64encode(content).decode('ascii')
		cmd = ['bash', '-c',
			'echo %s | base64 -d > %s && chmod +x %s' % (
				encoded, dest_path, dest_path)]
		cont.attach_wait(lxc.attach_run_command, cmd)

	# run ASLRay exploit inside the container
	def run_aslray(self, cont, binary_path, buffer_size,
				   shellcode=None, timeout=60):

		fd = open('aslray_output', 'w')
		fd_err = open('aslray_error', 'w')

		print("starting container for ASLRay exploit...")
		cont.start()

		# copy ASLRay.sh into the container
		self.push_file(cont, self.aslray_path, '/tmp/ASLRay.sh')

		# make the target binary executable
		cont.attach_wait(lxc.attach_run_command,
			['chmod', '777', binary_path])

		# build the ASLRay command
		aslray_cmd = 'source /tmp/ASLRay.sh %s %d' % (
			binary_path, buffer_size)
		if shellcode:
			aslray_cmd += ' %s' % shellcode

		# wrap with timeout to prevent infinite exploit loops
		if timeout:
			cmd_list = ['timeout', '--signal=KILL', str(timeout),
				'bash', '-c', aslray_cmd]
		else:
			cmd_list = ['bash', '-c', aslray_cmd]

		cont.attach_wait(lxc.attach_run_command, cmd_list,
			stdout=fd, stderr=fd_err)

		fd.close()
		fd_err.close()

		print("stopping container...")
		cont.stop()

	# run ASLRay with perf stat monitoring inside the container
	# output is written to 'output' and 'perf_out' for DataParser compatibility
	def cmd_aslray(self, cont, binary_path, buffer_size, perf_events,
				   shellcode=None, timeout=60):

		fd = open('output', 'w')
		fd_perf = open('perf_out', 'w')

		print("starting container for ASLRay with perf monitoring...")
		cont.start()

		# copy ASLRay.sh into the container
		self.push_file(cont, self.aslray_path, '/tmp/ASLRay.sh')

		# make the target binary executable
		cont.attach_wait(lxc.attach_run_command,
			['chmod', '777', binary_path])

		# build ASLRay command
		aslray_cmd = 'source /tmp/ASLRay.sh %s %d' % (
			binary_path, buffer_size)
		if shellcode:
			aslray_cmd += ' %s' % shellcode

		# wrap with timeout
		if timeout:
			inner = 'timeout --signal=KILL %d bash -c \'%s\'' % (
				timeout, aslray_cmd)
		else:
			inner = 'bash -c \'%s\'' % aslray_cmd

		# wrap with perf stat for HPC data collection
		perf_cmd = ['bash', '-c',
			'perf stat -I 10 -e %s -x, %s' % (perf_events, inner)]

		cont.attach_wait(lxc.attach_run_command, perf_cmd,
			stdout=fd, stderr=fd_perf)

		fd.close()
		fd_perf.close()

		print("stopping container...")
		cont.stop()
