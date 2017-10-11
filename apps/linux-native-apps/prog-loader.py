from cmd import Cmd
import argparse
import commands
import readline

from vale_bpf import VALE_BPF


parser = argparse.ArgumentParser(description='vale-bpf-ctl')
parser.add_argument('-s', '--switch')
parser.add_argument('-a', '--attach', action='store_true')
parser.add_argument('-p', '--program')
parser.add_argument('-f', '--func_name')
parser.add_argument('-t', '--trace', action='store_true')
parser.add_argument('-d', '--detach', action='store_true')


def do_trace(bpf):
    bpf.trace_print()


def attach(program, switch, func_name, trace):
    b = VALE_BPF(src_file=program)
    b.attach_vale_bpf(switch, func_name)

    if trace:
        try:
            do_trace(b)
        except KeyboardInterrupt:
            pass

    b.cleanup()


def detach(switch):
    b = VALE_BPF()
    b.remove_vale_bpf(switch)


if __name__ == '__main__':
    args = parser.parse_args()

    if args.attach and args.detach:
        print "Can't specify both of [a]ttach and [d]etach"
    elif args.attach:
        attach(args.program, args.switch, args.func_name, args.trace)
    elif args.detach:
        detach(args.switch)
    else:
        print "Please specify [a]ttach or [d]etach"
