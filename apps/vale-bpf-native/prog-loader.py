from cmd import Cmd
import argparse
import commands
import readline

from vale_bpf_native import VALE_BPF_NATIVE


parser = argparse.ArgumentParser(description='vale-bpf-native program loader')
parser.add_argument('-s', '--switch')
parser.add_argument('-a', '--attach', action='store_true')
parser.add_argument('-p', '--program')
parser.add_argument('-f', '--func_name')
parser.add_argument('-d', '--detach', action='store_true')


def attach(program, switch, func_name):
    b = VALE_BPF_NATIVE(src_file=program)
    b.attach_vale_bpf_native(switch, func_name)
    b.trace_print()
    b.cleanup()


def detach(switch):
    b = VALE_BPF_NATIVE()
    b.remove_vale_bpf_native(switch)


if __name__ == '__main__':
    args = parser.parse_args()

    if args.attach and args.detach:
        print "Can't specify both of [a]ttach and [d]etach"
    elif args.attach:
        attach(args.program, args.switch, args.func_name)
    elif args.detach:
        detach(args.switch)
    else:
        print "Please specify [a]ttach or [d]etach"
