#!/usr/bin/env python

from GenesisMiner import GenesisMiner
from optparse import OptionGroup, OptionParser
from time import sleep
from util import tokenize
from version import VERSION
import log




usage = "usage: %prog [OPTION]... \n"
parser = OptionParser(version=VERSION, usage=usage)
parser.add_option('--verbose',        dest='verbose',        action='store_true', help='verbose output, suitable for redirection to log file')
parser.add_option('-q', '--quiet',    dest='quiet',          action='store_true', help='suppress all output except hash rate display')
parser.add_option('--no-ocl',         dest='no_ocl',         action='store_true', help="don't use OpenCL")
parser.add_option('-d', '--device',   dest='device',         default=[],          help='comma separated device IDs, by default will use all (for OpenCL - only GPU devices)')

group = OptionGroup(parser, "Miner Options")
group.add_option('-r', '--rate',          dest='rate',       default=1,       help='hash rate display interval in seconds, default=1 (60 with --verbose)', type='float')
group.add_option('-e', '--estimate',      dest='estimate',   default=900,     help='estimated rate time window in seconds, default 900 (15 minutes)', type='int')
group.add_option('--cutoff-temp',         dest='cutoff_temp',default=[],      help='AMD GPUs, BFL only. For GPUs requires github.com/mjmvisser/adl3. Comma separated temperatures at which to skip kernel execution, in C, default=95')
group.add_option('--cutoff-interval',     dest='cutoff_interval',default=[],  help='how long to not execute calculations if CUTOFF_TEMP is reached, in seconds, default=0.01')

group = OptionGroup(parser,
	"OpenCL Options",
	"Every option except 'platform' and 'vectors' can be specified as a comma separated list. "
	"If there aren't enough entries specified, the last available is used. "
	"Use --vv to specify per-device vectors usage."
)
group.add_option('-p', '--platform', dest='platform',   default=-1,          help='use platform by id', type='int')
group.add_option('-w', '--worksize', dest='worksize',   default=[],          help='work group size, default is maximum returned by OpenCL')
group.add_option('-f', '--frames',   dest='frames',     default=[],          help='will try to bring single kernel execution to 1/frames seconds, default=30, increase this for less desktop lag')
group.add_option('-s', '--sleep',    dest='frameSleep', default=[],          help='sleep per frame in seconds, default 0')
group.add_option('--vv',             dest='vectors',    default=[],          help='use vectors, default false')
group.add_option('-v', '--vectors',  dest='old_vectors',action='store_true', help='use vectors')
parser.add_option_group(group)

(options, options.servers) = parser.parse_args()

log.verbose = options.verbose
log.quiet = options.quiet

options.rate = max(options.rate, 60) if options.verbose else max(options.rate, 0.1)

options.version = VERSION

options.max_update_time = 60

options.device = tokenize(options.device, 'device', [])

options.cutoff_temp = tokenize(options.cutoff_temp, 'cutoff_temp', [95], float)
options.cutoff_interval = tokenize(options.cutoff_interval, 'cutoff_interval', [0.01], float)

switch = None                 #main process object which controls mining threads

try:
	switch = GenesisMiner(options)

	if not options.no_ocl:
		import OpenCLMiner
		for miner in OpenCLMiner.initialize(options):
			switch.add_miner(miner)


	for miner in switch.miners:
		miner.start()

	switch.loop()

except KeyboardInterrupt:
	log.say_line('process intrrupted...!')
finally:
	log.say_line("final processess...!")
	for miner in switch.miners:
		miner.stop()
	if switch: switch.stop()

	if not options.no_ocl:
		OpenCLMiner.shutdown()
sleep(1.1)
