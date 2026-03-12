import pandas as pd
import re
import os
from collections import defaultdict

""" Parse perf file to create csv """
class Parser(object):

	def __init__(self, result_dir='results/', perf_file='perf_out'):
		self.result_dir = result_dir
		self.perf_file = perf_file
		os.makedirs(self.result_dir, exist_ok=True)

	def parse(self, num):
		fd_perf = open(self.perf_file, 'r')
		
		d_data = defaultdict(list)
		
		search = re.findall(r'\s+[\d.].+,(.+),,([^,]+),.+', fd_perf.read())

		for val,event in search:
			if val == '<not counted>':
				pass
			else:
				d_data[event].append(val)

		df = pd.DataFrame(list(d_data.values()), index=list(d_data.keys()))
		df = df.transpose()
		
		df.to_csv(os.path.join(self.result_dir, str(num)), index=None)

		fd_perf.close()
