from Source import Source
from binascii import hexlify, unhexlify
import hashlib
from json import dumps, loads
from log import say_exception, say_line
from struct import pack
from threading import Lock
from time import sleep, time
from util import chunks, Object
import asyncore
import struct
from construct import *




BASE_DIFFICULTY = 0x00000000FFFF0000000000000000000000000000000000000000000000000000


class GenesisSource(Source):
	def __init__(self, switch):
		super(GenesisSource, self).__init__(switch)
		self.channel_map = {}
		self.subscribed = False
		self.authorized = None
		self.submits = {}
		self.last_submits_cleanup = time()
		self.current_difficulty = BASE_DIFFICULTY
		self.jobs = {}
		self.current_job = None
		self.extranonce = ''
		self.extranonce2_size = 4
		self.send_lock = Lock()
		self.merkle_root = ''

		self.bits = ''

	def loop(self):
		super(GenesisSource, self).loop()

		self.switch.update_time = False

		while True:
			if self.should_stop: return



			miner = self.switch.updatable_miner()
			while miner:
				self.current_job = self.refresh_job(self.current_job)

				self.queue_work(self.current_job, miner)

				miner = self.switch.updatable_miner()

			with self.send_lock:
				self.process_result_queue()

			sleep(1)

	def authorize(self):
		return True
	def asyncore_thread(self):
		asyncore.loop(map=self.channel_map)

	def stop(self):
		self.should_stop = True

	def create_input_script(self, psz_timestamp):
  		psz_prefix = ""
  		#use OP_PUSHDATA1 if required
  		if len(psz_timestamp) > 76: psz_prefix = '4c'

  		script_prefix = '04ffff001d0104' + psz_prefix + chr(len(psz_timestamp)).encode('hex')
  		#logging.info(script_prefix + psz_timestamp.encode('hex'))
  		return (script_prefix + psz_timestamp.encode('hex')).decode('hex')


	def create_output_script(self, pubkey):
  		script_len = '41'
  		OP_CHECKSIG = 'ac'
  		return (script_len + pubkey + OP_CHECKSIG).decode('hex')

	def create_transaction(self, input_script, output_script, value):
  		transaction = Struct("transaction", Bytes("version", 4), Byte("num_inputs"), StaticField("prev_output", 32), UBInt32('prev_out_idx'), Byte('input_script_len'), Bytes('input_script', len(input_script)), UBInt32('sequence'), Byte('num_outputs'), Bytes('out_value', 8), Byte('output_script_len'), Bytes('output_script',  0x43), UBInt32('locktime'))
  		tx = transaction.parse('\x00'*(127 + len(input_script)))
  		tx.version           = struct.pack('<I', 1)
  		tx.num_inputs        = 1
  		tx.prev_output       = struct.pack('<qqqq', 0,0,0,0)
  		tx.prev_out_idx      = 0xFFFFFFFF
  		tx.input_script_len  = len(input_script)
  		tx.input_script      = input_script
  		tx.sequence          = 0xFFFFFFFF
  		tx.num_outputs       = 1
  		tx.out_value         = struct.pack('<q' , value)#0x000005f5e100)#012a05f200) #50 coins
  		#tx.out_value         = struct.pack('<q' ,0x000000012a05f200) #50 coins
  		tx.output_script_len = 0x43
  		tx.output_script     = output_script
  		tx.locktime          = 0
  		return transaction.build(tx)

	def create_block_header(self, hash_merkle_root, time, bits, nonce):
  		block_header = Struct("block_header",
    		Bytes("version",4),
    		Bytes("hash_prev_block", 32),
    		Bytes("hash_merkle_root", 32),
    		Bytes("time", 4),
    		Bytes("bits", 4),
    		Bytes("nonce", 4))
  		genesisblock = block_header.parse('\x00'*80)
  		genesisblock.version          = struct.pack('<I', 1)
  		genesisblock.hash_prev_block  = struct.pack('<qqqq', 0,0,0,0)
  		genesisblock.hash_merkle_root = hash_merkle_root
  		genesisblock.time             = struct.pack('<I', time)
  		genesisblock.bits             = struct.pack('<I', bits)
  		genesisblock.nonce            = struct.pack('<I', nonce)
  		return block_header.build(genesisblock)


	def refresh_job(self, job):
		if job == None:
			job = Object()
			job.job_id = '0'
			job.prevhash = '0000000000000000000000000000000000000000000000000000000000000000'
			job.version = '00000001'
			job.nbits = '12028280'
			#job.nbits = '1c028280'
			#job.nbits = '1d00ffff'
			job.ntime = '59915BBE'  #ntime in hex format
			# j.ntime = '595913da'
			job.extranonce2 = '00000'
			# j.extranonce2 = '000000'
			job.merkle_branch = ''
			job.psztimestamp = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"
			job.pubkey = "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f"
			job.genesis_coinbase_reward = 5000000000
		job.extranonce2 = self.increment_nonce(job.extranonce2)
		job.ntime = self.increment_nonce(job.ntime)
		say_line("processing ntime = %s" , int(job.ntime , 16))  #print ntime in int format


		self.merkle_root = (hashlib.sha256(hashlib.sha256(self.create_transaction(
			self.create_input_script(job.psztimestamp),
			self.create_output_script(
				job.pubkey),
			job.genesis_coinbase_reward)).digest()).digest())
		merkle_root_reversed = ''
		for word in chunks(self.merkle_root, 4):
			merkle_root_reversed += word[::-1]
		merkle_root = hexlify(merkle_root_reversed)
		self.bits = int(job.nbits, 16)
		self.current_difficulty = (self.bits & 0xffffff) * 2 ** (8 * ((self.bits >> 24) - 3))


		job.block_header = ''.join([job.version, job.prevhash, merkle_root, job.ntime, job.nbits])

		self.jobs[job.job_id] = job
		self.current_job = job

		return job


	def increment_nonce(self, nonce):
		next_nonce = long(nonce, 16) + 1
		if len('%x' % next_nonce) > (self.extranonce2_size * 2):
			return '00' * self.extranonce2_size
		return ('%0' + str(self.extranonce2_size * 2) +'x') % next_nonce

	def subscribe(self):
		return True

	def queue_work(self, work, miner=None):
		target = ''.join(list(chunks('%064x' % self.current_difficulty, 2))[::-1])
		self.switch.queue_work(self, work.block_header, target, work.job_id, work.extranonce2, miner)
