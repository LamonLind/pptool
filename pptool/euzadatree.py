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


from collections import namedtuple
from math import log
import re


class Tree:
    def __init__(self, elf_class, instruct_list, color, addr_only):
        self.elf_class = elf_class
        self.instruct_list = instruct_list
        self.addr_only = addr_only
        Color = namedtuple("Color", ["addr", "ofs", "ppo", "reg", "imm", "hex", "rst"])
        if color:
            self.color = Color(
                "\x1b[38;5;193m",
                "\x1b[38;5;229m",
                "\x1b[38;5;215m",
                "\x1b[38;5;117m",
                "\x1b[38;5;217m",
                "\x1b[38;5;102m",
                "\x1b[0m",
            )
        else:
            self.color = Color("", "", "", "", "", "", "")

    def disass(self, ass):
        return self.disass_32(ass) if self.elf_class == 1 else self.disass_64(ass)

    def disass_32(self, ass):
        r = ""
        for ins in ass[:4], ass[4:]:
            f_ins, reg_t, reg_n, imm, ob, cb = "", "", "", "", "", ""
            reg_t_name = "r"
            reg_n_name = "r"
            ins_val = int.from_bytes(ins, "little")
            if ins.endswith(b"\xe2"):
                f_ins = "add "
            elif ins.endswith(b"\xe5"):
                f_ins = "ldr "
            else:
                continue
            reg_names = {14: "lr"}
            reg_t = (ins_val >> 0xC) & 0xF
            if reg_t in reg_names:
                reg_t_name = reg_names[reg_t]
                reg_t = ""
            reg_n = (ins_val >> 0x10) & 0xF
            if reg_n in reg_names:
                reg_n_name = reg_names[reg_n]
                reg_n = ""
            imm = ins_val & 0xFFF
            if f_ins == "ldr ":
                ob = "["
                cb = "]"
            else:
                rotation = imm >> 8
                imm &= 0xFF
                for _ in range(rotation):
                    imm = (imm << 30 | imm >> 2) & 0xFFFFFFFF
            imm = str(imm) if imm < 0xA else hex(imm)
            r += (
                11 * " "
                + f_ins
                + self.color.reg
                + f"{reg_t_name}{reg_t}"
                + self.color.rst
                + ", "
            )
            r += (
                f"{ob}{self.color.reg}{reg_n_name}{reg_n}{self.color.rst}, "
                + f"{self.color.imm}{imm}{self.color.rst}{cb}"
                + " \n"
            )
        r += self.color.hex
        r += 11 * " " + " ".join(re.findall("..", ass.hex().upper())) + "\n"
        r += self.color.rst
        return r

    def disass_64(self, ass):
        r = ""
        for ins in ass[:4], ass[4:]:
            f_ins, reg_t, reg_n, imm, ob, cb, lsl = "", "", "", "", "", "", ""
            reg_t_name = "x"
            ins_val = int.from_bytes(ins, "little")
            if ins.endswith(b"\x91"):
                f_ins = "add "
            elif re.compile(b"(?s:...)[\xf9\xfd\xbd\x7d\x3d]").match(ins):
                f_ins = "ldr "
            else:
                continue
            shift = ins_val >> 0x16
            reg_t = ins_val & 0x1F
            reg_n = ins_val >> 5 & 0x1F
            imm = ins_val >> 0xA & 0xFFF
            if f_ins == "ldr ":
                reg_t_name = {
                    0x3E5: "x",
                    0x3F5: "d",
                    0x2F5: "s",
                    0x1F5: "h",
                    0xF7: "q",
                }[shift]
                imm <<= 3
                ob = "["
                cb = "]"
            elif shift == 0x245:
                lsl = ", lsl " + self.color.imm + "12" + self.color.rst
            imm = str(imm) if imm < 0xA else hex(imm)
            r += (
                11 * " "
                + f_ins
                + self.color.reg
                + f"{reg_t_name}{reg_t}"
                + self.color.rst
                + ", "
            )
            r += (
                f"{ob}{self.color.reg}x{reg_n}{self.color.rst}, "
                + f"{self.color.imm}{imm}{self.color.rst}{lsl}{cb}"
                + " \n"
            )
        r += self.color.hex
        r += 11 * " " + " ".join(re.findall("..", ass.hex().upper())) + "\n"
        r += self.color.rst
        return r

    def shine(self):
        r = ""
        if self.instruct_list:
            for instruct in self.instruct_list:
                r += (
                    self.color.ppo
                    + "\n----------    "
                    + f"pp+{instruct.pp_offset}"
                    + "    ----------\n\n"
                    + self.color.rst
                )
                if instruct.valid:
                    if instruct.match_list:
                        r += "      FUNCTION  OBJECT    OFFSET\n\n"
                        i = 1
                        for match in instruct.match_list:
                            addresses = (
                                self.color.ofs
                                + f"{match.function}"
                                + self.color.addr
                                + f"  {match.address}"
                                + self.color.ofs
                                + f"  {hex(int(match.address, 16) - int(match.function, 16))}\n"
                                if match.function is not None
                                else self.color.addr + f"{match.address}\n"
                            )
                            r += (
                                f"･{i} "
                                + (3 - int(log(i, 10))) * " "
                                + addresses
                                + self.color.rst
                            )
                            r += (
                                self.disass(match.assembly)
                                if not self.addr_only
                                else ""
                            )
                            i += 1
                    else:
                        r += 6 * " " + self.color.addr + "no match\n" + self.color.rst
                else:
                    r += (
                        6 * " "
                        + self.color.addr
                        + "pp+offset not valid\n"
                        + self.color.rst
                    )
        return r
