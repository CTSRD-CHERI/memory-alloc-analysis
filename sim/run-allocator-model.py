#!/usr/bin/env python3

import argparse
import importlib.machinery
import importlib.util
import logging
import sys

if __name__ == "__main__" and __package__ is None:
    import os
    sys.path.append(os.path.dirname(sys.path[0]))

from common.run import Run
from common.unrun import Unrun

# Parse command line arguments
argp = argparse.ArgumentParser(description='Interpret an allocation trace')
# argp.add_argument('--use-allocated-size', action='store_true',
#                   help="Ignore procstat information and use the "
#                        "allocator's idea of how big the heap is")
argp.add_argument('allocator', action='store',
                  help="Pick allocator to use")
argp.add_argument("--log-level", help="Set the logging level",
                  choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                  default="INFO")
argp.add_argument('remainder', nargs=argparse.REMAINDER,
                  help="Arguments fed to allocator model")
args = argp.parse_args()

# Set up logging
logging.basicConfig(level=logging.getLevelName(args.log_level))

# This cannot possibly be the right answer
allocspecs = importlib.util.find_spec(args.allocator)
if allocspecs is None :
    allocspecs = importlib.util.find_spec("alloc." + args.allocator)
if allocspecs is None :
    print("Unable to find allocator %s" % args.allocator, file=sys.stderr)
    sys.exit(1)

allocmod   = importlib.util.module_from_spec(allocspecs)
allocspecs.loader.exec_module(allocmod)

alloc = allocmod.Allocator(cliargs=args.remainder)

# XXX OLD
# if args.use_allocated_size :
#   szcb = lambda : alloc.size
# else :
#   szcb = lambda : parser.addr_space_size

run = Run(sys.stdin)
unrun = Unrun(lambda : run.timestamp_ns, out=sys.stdout)
 
run._trace_listeners += [ alloc ]
run._addr_space_sample_listeners += [ alloc ]
alloc.register_subscriber( unrun )

run.replay()
