import hashlib
from log import say_exception, say_line, say_quiet
from sha256 import hash, sha256, STATE
from struct import pack, unpack
from threading import RLock
from time import time, sleep
from util import Object, chunks, bytereverse, belowOrEquals, uint32
from GenesisSource import GenesisSource
import OpenCLMiner
import log



class GenesisMiner(object):
	def __init__(self, options):
		self.lock = RLock()
		self.miners = []
		self.options = options
		self.last_work = 0
		self.update_time = False
		self.max_update_time = 3600
		self.source = GenesisSource(self)   #Genesis miner source information

		self.user_agent = 'poclbm/' + options.version

		self.difficulty = 0
		self.true_target = None
		self.last_block = ''

		self.sent = {}
		say_line("Genesis Miner object created!")





	def add_miner(self, miner):
		self.miners.append(miner)
		miner.switch = self

	def updatable_miner(self):
		for miner in self.miners:
			if miner.update:
				miner.update = False
				return miner

	def announce(self  , header_hash , ntime , nBits):
		say_line("Genesis Hash: " + (header_hash).encode('hex_codec'))
		say_line("Merkle root: " + (self.source.merkle_root[::-1].encode('hex_codec')))
		say_line("psztimestamp: " + (self.source.current_job.psztimestamp))
		say_line("pubkey Address: " + (self.source.current_job.pubkey))
		say_line("ntime: " + (str(ntime)))
		say_line("nonce: " + (str(nBits)))
		say_line("genesis coinbase reward: " + (str(self.source.current_job.genesis_coinbase_reward)))

	def loop(self):
		self.should_stop = False

		while True:
			if self.should_stop: return
			self.source.loop()
			sleep(1)





	#callers must provide hex encoded block header and target
	def decode(self, container, block_header, target, job_id = None, extranonce2 = None):
		if block_header:
			job = Object()
			binary_data = block_header.decode('hex')
			data0 = list(unpack('<16I', binary_data[:64])) + ([0] * 48)
 			job.target		= unpack('<8I', target.decode('hex'))
			job.header		= binary_data[:68]
			job.merkle_end	= uint32(unpack('<I', binary_data[64:68])[0])
			job.time		= uint32(unpack('<I', binary_data[68:72])[0])
			job.difficulty	= uint32(unpack('<I', binary_data[72:76])[0])
			job.state		= sha256(STATE, data0)
			job.targetQ		= 2**256 / int(''.join(list(chunks(target, 2))[::-1]), 16)
			job.job_id		= job_id
			job.extranonce2	= extranonce2
			job.container		= container

			if job.difficulty != self.difficulty:
				self.set_difficulty(job.difficulty)

			return job

	def set_difficulty(self, difficulty):

		self.difficulty = difficulty
		bits = '%08x' % bytereverse(difficulty)
		true_target = '%064x' % (int(bits[2:], 16) * 2 ** (8 * (int(bits[:2], 16) - 3)),)
		true_target = ''.join(list(chunks(true_target, 2))[::-1])
		self.true_target = unpack('<8I', true_target.decode('hex'))

	def send(self, result):
		for nonce in result.miner.nonce_generator(result.nonces):

			h = hash(result.state, result.merkle_end, result.time, result.difficulty, nonce)

			if h[7] != 0:
				hash6 = pack('<I', long(h[6])).encode('hex')
				say_line('Verification failed, check hardware! (%s, %s)', (result.miner.id(), hash6))
				return True # consume this particular result
			else:
				self.diff1_found(bytereverse(h[6]), result.target[6])
				if belowOrEquals(h[:7], result.target[:7]):
					is_block = belowOrEquals(h[:7], self.true_target[:7])

					hash6 = pack('<I', long(h[6])).encode('hex')
					hash5 = pack('<I', long(h[5])).encode('hex')
					self.sent[nonce] = (is_block, hash6, hash5)
					ntime = long(pack('<I', long(result.time)).encode('hex'),16)
					resnonce = long(pack('<I', long(nonce)).encode('hex'),16)
					block = self.source.create_block_header(self.source.merkle_root, ntime, self.source.bits, resnonce)
					hash_header = hashlib.sha256(hashlib.sha256(block).digest()).digest()[::-1]
					shouldSend = int(hash_header.encode('hex_codec'), 16) < self.source.current_difficulty
					self.announce(hash_header,ntime,resnonce)
					self.should_stop = True
					if shouldSend:
						return False

		return True

	def diff1_found(self, hash_, target):
		if self.options.verbose and target < 0xFFFF0000L:
			say_line('checking %s <= %s', (hash_, target))

	def status_updated(self, miner):
		verbose = self.options.verbose
		rate = miner.rate if verbose else sum([m.rate for m in self.miners])
		estimated_rate = miner.estimated_rate if verbose else sum([m.estimated_rate for m in self.miners])
		rejected_shares = miner.share_count[0] if verbose else sum([m.share_count[0] for m in self.miners])
		total_shares = rejected_shares + miner.share_count[1] if verbose else sum([m.share_count[1] for m in self.miners])
		total_shares_estimator = max(total_shares, 1)
		say_quiet('%s[%.03f MH/s]', (str(miner.nonces_left), rate))



	def queue_work(self, container, block_header, target = None, job_id = None, extranonce2 = None, miner=None):
		work = self.decode(container, block_header, target, job_id, extranonce2)
		with self.lock:
			if not miner:
				miner = self.miners[0]
				for i in xrange(1, len(self.miners)):
					self.miners[i].update = True
			miner.work_queue.put(work)
			if work:
				miner.update = False; self.last_work = time()
				if self.last_block != work.header[25:29]:
					self.last_block = work.header[25:29]
					self.clear_result_queue(container)

	def clear_result_queue(self, container):
		while not container.result_queue.empty():
			container.result_queue.get(False)
	def stop(self):
		self.should_stop = True
		self.source.stop()
	def put(self, result):
		result.container.result_queue.put(result)
