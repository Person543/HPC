#!/usr/bin/env python3
from Container import Container
from DataParser import Parser
import argparse
import subprocess
import socket
import sys
import os

DEFAULT_EVENTS = 'L1-dcache-load-misses,L1-dcache-loads,L1-dcache-stores,L1-icache-load-misses,LLC-load-misses,LLC-loads,branch-loads,iTLB-load-misses'

# directory where this script lives (and where test.c / ASLRay.sh are)
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def build_test_binary():
	"""Compile test.c into an exploitable binary. Returns the path to the binary."""
	src = os.path.join(SCRIPT_DIR, 'test.c')
	out = os.path.join(SCRIPT_DIR, 'test')

	if not os.path.isfile(src):
		print("error: test.c not found at %s" % src)
		sys.exit(1)

	# always recompile to ensure flags are correct
	print("compiling test.c -> test  (gcc -z execstack -fno-stack-protector)")
	ret = subprocess.call(
		['gcc', '-z', 'execstack', '-fno-stack-protector', src, '-o', out])
	if ret != 0:
		print("error: gcc failed (return code %d). Is gcc installed?" % ret)
		sys.exit(1)

	# make suid so ASLRay can exploit it
	os.chmod(out, 0o4755)
	print("built: %s" % out)
	return out


def discover_binaries(directory):
	"""Auto-discover files in a directory."""
	binaries = []
	for name in sorted(os.listdir(directory)):
		path = os.path.join(directory, name)
		if os.path.isfile(path) and not name.startswith('.'):
			binaries.append(name)
	return binaries


def is_net_on():
	try:
		host = socket.gethostbyname('www.google.com')
		s = socket.create_connection((host, 80), 2)
		return True
	except Exception:
		return False


def build_parser():
	parser = argparse.ArgumentParser(
		description='HPC data collector - run binaries inside LXC containers with perf stat monitoring. '
			'By default, compiles the bundled test.c and runs ASLRay against it. '
			'No arguments required for the default workflow.')

	# container settings
	parser.add_argument('--container', default='new-cont',
		help='name of the LXC container to use (default: new-cont)')
	parser.add_argument('--clone-name', default='tmp-cont',
		help='name for the cloned container (default: tmp-cont)')

	# mode selection
	parser.add_argument('--direct', action='store_true',
		help='use direct execution mode instead of ASLRay (default: ASLRay mode)')

	# optional: custom sample directory
	parser.add_argument('--sample-dir', default=None,
		help='optional: directory containing binary samples to run. '
			'If omitted, compiles and uses the bundled test.c binary')
	parser.add_argument('--sample-list', default=None,
		help='optional: text file listing specific sample names (one per line). '
			'Only used with --sample-dir')

	# perf events
	parser.add_argument('--events', default=DEFAULT_EVENTS,
		help='comma-separated perf events to monitor (default: %(default)s)')

	# output
	parser.add_argument('--result-dir', default='results/',
		help='directory to store parsed CSV results (default: results/)')

	# ASLRay-specific options
	aslray_group = parser.add_argument_group('ASLRay options')
	aslray_group.add_argument('--buffer', type=int, default=1024,
		help='buffer size for ASLRay exploit (default: 1024)')
	aslray_group.add_argument('--shellcode', default=None,
		help='custom shellcode for ASLRay (e.g. \'\\x31\\xc0...\')')
	aslray_group.add_argument('--timeout', type=int, default=60,
		help='seconds before killing the ASLRay exploit loop (default: 60)')

	# safety
	parser.add_argument('--allow-network', action='store_true',
		help='skip the internet safety check (default: exit if network is on)')

	return parser


if __name__ == "__main__":

	args = build_parser().parse_args()

	if not args.allow_network and is_net_on():
		print("****************************")
		print("Warning : Turn off the Internet!!")
		print("****************************")
		print("exiting...")
		sys.exit(1)

	# determine what binaries to run
	if args.sample_dir:
		# user supplied a custom sample directory
		sample_dir = args.sample_dir
		if not os.path.isdir(sample_dir):
			print("error: sample directory not found: %s" % sample_dir)
			sys.exit(1)

		if not sample_dir.endswith('/'):
			sample_dir += '/'

		if args.sample_list:
			if not os.path.isfile(args.sample_list):
				print("error: sample list not found: %s" % args.sample_list)
				sys.exit(1)
			with open(args.sample_list, 'r') as fd:
				l_samples = [line.strip() for line in fd.read().split('\n') if line.strip()]
		else:
			l_samples = discover_binaries(sample_dir)

		if not l_samples:
			print("error: no samples found in %s" % sample_dir)
			sys.exit(1)

		print("found %d samples in %s" % (len(l_samples), sample_dir))
		push_binaries = False
	else:
		# default: compile and use the bundled test binary
		test_binary = build_test_binary()
		sample_dir = SCRIPT_DIR + '/'
		l_samples = [os.path.basename(test_binary)]
		push_binaries = True
		print("using bundled test binary: %s" % test_binary)

	cobj = Container(container_name=args.container, clone_name=args.clone_name)
	cont = cobj.get()

	if not args.direct:
		# ASLRay exploit mode (default)
		print("=== ASLRay Mode ===")
		print("binary dir: %s  buffer: %d  timeout: %ds" % (
			sample_dir, args.buffer, args.timeout))

		for num, name in enumerate(l_samples):
			print("%d -> %s (ASLRay)" % (num, name))
			clone = cobj.clone(cont)
			host_bin = "%s%s" % (sample_dir, name) if push_binaries else None
			binary_path = '/tmp/%s' % name if push_binaries else "%s%s" % (sample_dir, name)

			cobj.cmd_aslray(clone, binary_path,
				args.buffer, args.events,
				shellcode=args.shellcode,
				timeout=args.timeout,
				host_binary=host_bin)
			clone.destroy()

			p = Parser(result_dir=args.result_dir)
			p.parse(num)
	else:
		# Direct execution mode
		print("=== Direct Execution Mode ===")
		for num, name in enumerate(l_samples):
			print("%d -> %s" % (num, name))
			clone = cobj.clone(cont)
			host_bin = "%s%s" % (sample_dir, name) if push_binaries else None
			bin_path = '/tmp/%s' % name if push_binaries else "%s%s" % (sample_dir, name)

			cobj.cmd(clone, "chmod 777 %s" % bin_path, host_binary=host_bin)
			cobj.cmd(clone, "timeout 6s perf stat -I 10 -e %s -x, %s" % (
				args.events, bin_path), host_binary=host_bin)
			clone.destroy()

			p = Parser(result_dir=args.result_dir)
			p.parse(num)
