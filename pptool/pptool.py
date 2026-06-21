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


from .instruct import Instruct32, Instruct64
from .euzadatree import Tree
from json import dumps
from mmap import mmap
from os import path
from typing import NamedTuple
from re import findall


class Match(NamedTuple):
    address: str
    register: int
    function: str
    assembly: bytes


class PPTool:
    def __init__(self):
        self.libapp = None
        self.elf_class = 0
        self.offsets = None
        self.instruct_list = None

    def addresses(self):
        return {
            offset: (
                match["address"] if "address" in match else match
                for match in match_list
            )
            for offset, match_list in self.matches().items()
        }

    def func_bytes(self):
        return (
            b"\xfdy\xbf\xa9\xfd\x03\x0f\xaa" if self.elf_class == 2 else b"\x00H-\xe9"
        )

    def json(self):
        if matches := self.matches():
            return dumps(matches, indent=2)
        return ""

    def matches(self):
        matches = {}
        self.search()
        if instruct_list := self.instruct_list:
            for instruct in instruct_list:
                if instruct.valid:
                    if instruct.match_list:
                        matches[instruct.pp_offset] = [
                            match._replace(
                                assembly = " ".join(
                                    findall("..", match.assembly.hex().upper())
                                )
                            )._asdict()
                            for match in instruct.match_list
                        ]
                    else:
                        matches[instruct.pp_offset] = ("no match",)
                else:
                    matches[instruct.pp_offset] = ("invalid pp+offset",)
        return matches

    def populate_instruct_list(self, mmap_obj):
        instruct = Instruct32 if self.elf_class == 1 else Instruct64
        self.instruct_list = [instruct(o) for o in self.offsets]
        for instruct in self.instruct_list:
            if instruct.valid:
                for reg in self.regs():
                    for match in instruct.pattern(reg).finditer(mmap_obj):
                        m_bytes = match.group()
                        if instruct.validate(m_bytes):
                            address = match.start()
                            instruct.match_list.append(
                                Match(
                                    hex(address),
                                    reg,
                                    hex(mmap_obj[:address].rfind(self.func_bytes())),
                                    m_bytes,
                                )
                            )
                instruct.match_list = sorted(
                    instruct.match_list, key=lambda m: m.address
                )

    def result(self, tree_color=True, hide_ass_disass=False):
        self.search()
        if self.instruct_list:
            return Tree(
                self.elf_class, self.instruct_list, tree_color, hide_ass_disass
            ).shine()
        return ""

    def regs(self):
        return (
            tuple(i for i in range(15)) + (16, 17, 19, 20, 23, 24, 25, 30)
            if self.elf_class == 2
            else (0, 1, 2, 3, 4, 6, 8, 9, 12, 14)
        )

    def search(self):
        if self.offsets:
            if self.libapp:
                with open(self.libapp, "rb") as f:
                    with mmap(
                        f.fileno(),
                        length=0,
                        access=1,
                    ) as mmap_obj:
                        self.set_elf_class(mmap_obj)
                        self.search_instr(mmap_obj)
            else:
                print("pptool: error: libapp is not set")
        else:
            print("pptool: error: offset list is required")

    def search_instr(self, mmap_obj):
        if self.elf_class:
            if (invalid := self.validate_offsets()) is None:
                self.populate_instruct_list(mmap_obj)
            else:
                print(
                    f"pptool: error: argument offset: invalid offset value: '{invalid}'"
                )
        else:
            print("pptool: error: argument libapp: unsupported file")

    def set_elf_class(self, mmap_obj):
        h = int.from_bytes(mmap_obj[0:5], "little")
        if h in (0x1464C457F, 0x2464C457F) and mmap_obj[18:20] in (
            b"(\x00",
            b"\xb7\x00",
        ):
            self.elf_class = h >> 0x20

    def set_libapp(self, libapp):
        self.libapp = None
        self.offsets = None
        self.instruct_list = None
        try:
            if path.isfile(libapp):
                self.libapp = libapp
            else:
                print(f"pptool: error: invalid path value: '{libapp}'")
        except TypeError:
            print("ptool: error: path should be string, bytes, os.PathLike or integer")

    def set_offsets(self, *ppo_seq):
        self.offsets = None
        self.instruct_list = None
        if ppo_seq[0]:
            if isinstance(ppo_seq[0], list):
                ppo_seq = ppo_seq[0]
            for ppo in ppo_seq:
                try:
                    ppo_int = int(ppo, 16)
                    if ppo_int <= 0:
                        print(f"pptool: error: invalid offset value: {ppo}")
                        return
                except ValueError:
                    print(f"pptool: error: invalid offset value: {ppo}")
                    return
                except TypeError:
                    print(f"pptool: error: invalid offset type: {type(ppo)}")
                    return
            self.offsets = sorted(
                list(set(offs.lower() for offs in ppo_seq)),
                key=lambda ppoffset: int(ppoffset, 16),
            )

    def simple(self):
        out = ""
        if addresses := self.addresses():
            out += "PP+offset Addresses"
            for ofs in addresses:
                l = "\n" + 10 * " "
                if address := addresses[ofs]:
                    out += f"\n{ofs}:{l}{l.join(address)}"
        return out

    def validate_offsets(self):
        for o in self.offsets:
            if isinstance(o, str):
                try:
                    o_int = int(o, 16)
                    if self.elf_class == 2 and (o_int < 0x10 or o_int > 0xFFFFFF):
                        return o
                    if self.elf_class == 1 and (o_int < 0x7 or o_int > 0xFFFFF):
                        return o
                except ValueError:
                    return None
        return None
