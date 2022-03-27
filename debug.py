#!/usr/bin/env python3

import argparse
import binascii
import ptrace

tracer = None

def main():
    global tracer
    arguments = parse_arguments()
    tracer = ptrace.TraceSession(arguments.pid)
    tracer.attach()

    dump_range(0x065cc000, 0x1390000)


def parse_arguments():
    parser = argparse.ArgumentParser(description="Very shitty gdb, but in python!")

    parser.add_argument("pid", type=int, help="Process ID of the process you wish to debug")

    return parser.parse_args()


def show_memory_sections(arguments):
    """
    Display summary of potentially interesting memory ranges
    :param arguments: Argparse argument namespace
    """
    lines = []
    with open("/proc/" + arguments.pid + "/maps", "r") as map_file:
        line = map_file.readline().split()
        while line:
            lines.append(line.split())
            line = map_file.readline()

    for line in lines:
        pass #TODO

def dump_range(offset: int, size: int):
    data = tracer.read_data(offset, size)

    for offset in data.keys():
        text = hex(swap64(data[offset]))[2:]
        while len(text) < 16:
            text = "0" + text
        print(offset + ": ", end="")
        print(text + ": ", end="")
        for byte in binascii.unhexlify(text):
            if 0x20 <= byte < 0x7f:
                print(chr(byte), end="")
            else:
                print(".", end="")
        print("")


def swap64(word):
    return int.from_bytes(word.to_bytes(8, byteorder='little'), byteorder='big', signed=False)


if __name__ == '__main__':
    main()
