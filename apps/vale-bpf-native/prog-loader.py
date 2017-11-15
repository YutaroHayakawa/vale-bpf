# Copyright 2017 Yutaro Hayakawa
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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
    print "Program %s successfully loaded into %s" % (func_name, switch)


def detach(switch):
    b = VALE_BPF_NATIVE(text="int foo(void *ctx) { return 0; }")
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
