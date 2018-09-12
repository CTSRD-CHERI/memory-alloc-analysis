#!/usr/bin/env python3

import argparse
import ast
import importlib.machinery
import importlib.util
import logging
import sys

if __name__ == "__main__" and __package__ is None:
    import os
    sys.path.append(os.path.dirname(sys.path[0]))

from common.run import Run, Unrun

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

# We'd like to write output, with logging, to a single file on occasion.
# (It makes debugging easier when both streams are temporally merged)
#
# Python doesn't give us very good control of its buffering options;
# we'd like to just line-buffer sys.stdout and sys.stderr both, so that
# even though they have separate buffers, if they were writing to the
# same file descriptor, things would work out.  However, because we can't
# (can't? easily?) do that, we can just assign one to the other so they
# share a single buffer and underlying fd.  In particular, we assign
# sys.stderr to be sys.stdout, so that all output emerges on fd 1.
argp.add_argument('--stdouterr', help='Equate sys.stdout and sys.stderr',
                  action='store_const', const=True, default=False)

argp.add_argument('--render-freq', action='store', type=int, default=None)
argp.add_argument('--render-dir', action='store', type=str, default="./tmp")
argp.add_argument('--render-geom', action='store', type=ast.literal_eval, default=(1024,1024))

argp.add_argument('remainder', nargs=argparse.REMAINDER,
                  help="Arguments fed to allocator model")
args = argp.parse_args()

if args.stdouterr :
  sys.stderr.close()
  sys.stderr = sys.stdout

# Set up logging
logging.basicConfig(level=logging.getLevelName(args.log_level))

# Prepare Run
run = Run(sys.stdin)
tslam = lambda : run.timestamp_ns

# This cannot possibly be the right answer
allocspecs = importlib.util.find_spec(args.allocator)
if allocspecs is None :
    allocspecs = importlib.util.find_spec("alloc." + args.allocator)
if allocspecs is None :
    print("Unable to find allocator %s" % args.allocator, file=sys.stderr)
    sys.exit(1)

allocmod   = importlib.util.module_from_spec(allocspecs)
allocspecs.loader.exec_module(allocmod)

alloc = allocmod.Allocator(tslam=tslam, cliargs=args.remainder)

# XXX OLD
# if args.use_allocated_size :
#   szcb = lambda : alloc.size
# else :
#   szcb = lambda : parser.addr_space_size

unrun = Unrun(tslam, out=sys.stdout)
 
run.register_trace_listener(alloc)
run.register_addr_space_sample_listener(alloc)
alloc.register_subscriber( unrun )

if (args.render_freq is not None):
  if getattr(alloc,'render',None) is None :
    print("Allocator lacks renderer.", file=sys.stderr)
    sys.exit(1)

  from PIL import Image

  class RenderTraceListener:
    __slots__ = ('count')
    def __init__(self) :
      self.count = 0
    def _common(self) :
      if self.count % args.render_freq == 0 :
        img = Image.new('RGB', args.render_geom)
        alloc.render(img)
        img.save("%s/%s.png" % (args.render_dir, run.timestamp_ns))
      self.count += 1
    def allocd(self,*a) : self._common()
    def freed(self,*a) : self._common()
    def reallocd(self,*a) : self._common()

  run._trace_listeners += [ RenderTraceListener() ]

run.replay()
