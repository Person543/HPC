#!/usr/bin/env python3
from Container import Container
from DataParser import Parser
import argparse
import socket
import sys
import os

DEFAULT_EVENTS = 'L1-dcache-load-misses,L1-dcache-loads,L1-dcache-stores,L1-icache-load-misses,LLC-load-misses,LLC-loads,branch-loads,iTLB-load-misses'

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
			'Supports both direct execution and ASLRay exploit modes.')

	# container settings
	parser.add_argument('--container', default='new-cont',
		help='name of the LXC container to use (default: new-cont)')
	parser.add_argument('--clone-name', default='tmp-cont',
		help='name for the cloned container (default: tmp-cont)')

	# mode selection
	parser.add_argument('--aslray', action='store_true',
		help='enable ASLRay exploit mode (default: direct execution mode)')

	# sample list
	parser.add_argument('--sample-dir', required=True,
		help='directory containing the binary samples to run')
	parser.add_argument('--sample-list', required=True,
		help='path to a text file listing sample names (one per line)')

	# perf events
	parser.add_argument('--events', default=DEFAULT_EVENTS,
		help='comma-separated perf events to monitor (default: %(default)s)')

	# output
	parser.add_argument('--result-dir', default='results/',
		help='directory to store parsed CSV results (default: results/)')

	# ASLRay-specific options
	aslray_group = parser.add_argument_group('ASLRay options (only used with --aslray)')
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

	# read sample list
	if not os.path.isfile(args.sample_list):
		print("error: sample list not found: %s" % args.sample_list)
		sys.exit(1)

	with open(args.sample_list, 'r') as fd:
		l_samples = [line.strip() for line in fd.read().split('\n') if line.strip()]

	if not l_samples:
		print("error: sample list is empty: %s" % args.sample_list)
		sys.exit(1)

	# ensure sample_dir ends with /
	sample_dir = args.sample_dir
	if not sample_dir.endswith('/'):
		sample_dir += '/'

	cobj = Container(container_name=args.container, clone_name=args.clone_name)
	cont = cobj.get()

	if args.aslray:
		# ASLRay exploit mode - run ASLRay inside containers with perf monitoring
		print("=== ASLRay Mode ===")
		print("binary dir: %s  buffer: %d  timeout: %ds" % (
			sample_dir, args.buffer, args.timeout))

		for num, name in enumerate(l_samples):
			print("%d -> %s (ASLRay)" % (num, name))
			clone = cobj.clone(cont)

			cobj.cmd_aslray(clone, "%s%s" % (sample_dir, name),
				args.buffer, args.events,
				shellcode=args.shellcode,
				timeout=args.timeout)
			clone.destroy()

			p = Parser(result_dir=args.result_dir)
			p.parse(num)
	else:
		# Direct execution mode - run samples with perf monitoring
		for num, name in enumerate(l_samples):
			print("%d -> %s" % (num, name))
			clone = cobj.clone(cont)

			cobj.cmd(clone, "chmod 777 %s%s" % (sample_dir, name))
			cobj.cmd(clone, "timeout 6s perf stat -I 10 -e %s -x, %s%s" % (
				args.events, sample_dir, name))
			clone.destroy()

			p = Parser(result_dir=args.result_dir)
			p.parse(num)
