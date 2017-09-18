from Queue import Queue
from time import time


class Source(object):
	def __init__(self, GenesisMiner):
		self.switch = GenesisMiner
		self.result_queue = Queue()
		self.options = GenesisMiner.options

	def loop(self):
		self.should_stop = False
		self.last_failback = time()

	def process_result_queue(self):
		while not self.result_queue.empty():
			result = self.result_queue.get(False)
			with self.switch.lock:
				if not self.switch.send(result):
					self.result_queue.put(result)
					self.stop()  #???
					break