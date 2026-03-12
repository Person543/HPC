import lxc
import os
import base64
import subprocess
import shutil
import sys

# generic container class
class Container(object):

	def __init__(self, container_name='new-cont', clone_name='tmp-cont'):
		self.container_name = container_name
		self.clone_name = clone_name
		self.aslray_path = os.path.join(
			os.path.dirname(os.path.abspath(__file__)), 'ASLRay.sh')

	# get available container, or create one if it doesn't exist
	def get(self):
		for cont_obj in lxc.list_containers(as_object=True):
			if cont_obj.name == self.container_name:
				print("found existing container: %s" % self.container_name)
				return cont_obj

		# container not found — create it automatically
		print("container '%s' not found, creating it..." % self.container_name)
		return self.create()

	# create a new LXC container
	def create(self):
		cont = lxc.Container(self.container_name)
		if cont.defined:
			print("container '%s' already exists" % self.container_name)
			return cont

		print("creating LXC container '%s' (ubuntu)..." % self.container_name)
		print("this may take a few minutes on first run...")

		if not cont.create('download', lxc.LXC_CREATE_QUIET,
				{'dist': 'ubuntu', 'release': 'focal', 'arch': 'amd64'}):
			raise RuntimeError(
				"failed to create container '%s'. "
				"Try running with sudo or check LXC installation." %
				self.container_name)

		print("container '%s' created successfully" % self.container_name)
		return cont

	# clone container
	def clone(self, cont):
		print("cloning container for test...")

		clone = cont.clone(self.clone_name, flags=lxc.LXC_CLONE_SNAPSHOT)

		if clone is None or clone.name != self.clone_name:
			raise RuntimeError("failed to clone container as '%s'" % self.clone_name)

		return clone

	# run command
	# host_binary: optional host-side binary path to push into the container
	# before running the command. The binary will be placed at /tmp/<basename>
	# and the command string should reference /tmp/<basename> instead of host path.
	def cmd(self, cont, command, host_binary=None):
		
		fd = open('output', 'w')
		fd_perf = open('perf_out', 'w')

		print("starting container..")
		cont.start()

		if host_binary:
			dest = '/tmp/%s' % os.path.basename(host_binary)
			self.push_file(cont, host_binary, dest)

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
	# host_binary: optional host-side binary path to push into container
	#   When set, binary is pushed to /tmp/<basename> and that path is used
	#   instead of binary_path for the exploit.
	def run_aslray(self, cont, binary_path, buffer_size,
				   shellcode=None, timeout=60, host_binary=None):

		fd = open('aslray_output', 'w')
		fd_err = open('aslray_error', 'w')

		print("starting container for ASLRay exploit...")
		cont.start()

		# copy ASLRay.sh into the container
		self.push_file(cont, self.aslray_path, '/tmp/ASLRay.sh')

		# if host_binary provided, push it into the container
		if host_binary:
			binary_path = '/tmp/%s' % os.path.basename(host_binary)
			self.push_file(cont, host_binary, binary_path)

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
	# host_binary: optional host-side binary path to push into container
	#   When set, binary is pushed to /tmp/<basename> and that path is used
	#   instead of binary_path for the exploit.
	def cmd_aslray(self, cont, binary_path, buffer_size, perf_events,
				   shellcode=None, timeout=60, host_binary=None):

		fd = open('output', 'w')
		fd_perf = open('perf_out', 'w')

		print("starting container for ASLRay with perf monitoring...")
		cont.start()

		# copy ASLRay.sh into the container
		self.push_file(cont, self.aslray_path, '/tmp/ASLRay.sh')

		# if host_binary provided, push it into the container
		if host_binary:
			binary_path = '/tmp/%s' % os.path.basename(host_binary)
			self.push_file(cont, host_binary, binary_path)

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
