# Copyright 2026 github.com/Kirlif

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

    # http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import argparse
from os import path as os_path
from .pptool import PPTool


def main():
    parser = argparse.ArgumentParser(
        description=(
            "PPTool finds the loading addresses of Dart objects in libapp.so\nthrough"
            " their pool pointer offset.\nARM64, ARM supported.\n\n"
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("-v", "--version", action="version", version="2.0")
    parser.add_argument("-c", action="store_false", help="use default color")
    parser.add_argument(
        "-d", action="store_true", help="don't display assembly/disassembly"
    )
    parser.add_argument("-s", action="store_true", help="create a simple output")
    parser.add_argument("-j", action="store_true", help="full output in JSON format")
    parser.add_argument("libapp", help="path to libapp.so", type=path)
    parser.add_argument(
        "offset",
        nargs="+",
        help=(
            "specify pool pointer offsets to be searched\nsequence of hex strings   "
            " \narm:   0x6 < offset < 0x100000  ; offset mod 4 = 3    \narm64: 0xf <"
            " offset < 0x1000000 ; offset mod 8 = 0"
        ),
        type=offset,
    )
    args = parser.parse_args()
    ppt = pptool()
    ppt.set_libapp(args.libapp)
    ppt.set_offsets(args.offset)
    if args.j:
        print(ppt.json())
    elif args.s:
        print(ppt.simple())
    else:
        print(ppt.result(args.c, args.d))


def path(string):
    if os_path.isfile(string):
        return string
    raise ValueError


def pptool():
    return PPTool()


def offset(pp_offset):
    try:
        ppo = int(pp_offset, 16)
        if ppo > 0:
            return pp_offset
        raise ValueError
    except Exception as exc:
        raise ValueError from exc


if __name__ == "__main__":
    main()
