#!/usr/bin/env python3

import argparse
from collections import namedtuple
from json import dumps
from math import log
from mmap import mmap
from os import path as os_path
from re import compile, escape, findall
import re
from typing import NamedTuple


class Instruct:
    def __init__(self, pp_offset):
        self.pp_offset = hex(int(pp_offset, 16))
        self.match_list = []
        self.valid = True
        self.ldr_imm = None
        self.add_imm = None
        self.add_imm2 = None
        self.immediates()

    def immediates(self):
        pass


class Instruct32(Instruct):
    def immediates(self):
        ppo = int(self.pp_offset, 16)
        if ppo % 4 - 3:
            self.valid = False
        if ppo >> 0xC:
            self.add_imm = self.modify_immediate(ppo & ~0xFFF)
            self.ldr_imm = ppo & 0xFFF
        else:
            self.ldr_imm = ppo

    def pattern(self, reg):
        if self.add_imm is None:
            ldr_bytes = (((0xE5950 | reg) << 0xC) | self.ldr_imm).to_bytes(4, "little")
            return compile(escape(ldr_bytes))
        add_bytes = (((0xE2850 | reg) << 0xC) | self.add_imm).to_bytes(4, "little")
        return compile(escape(add_bytes) + b"(?s:...)\xe5")

    def modify_immediate(self, imm):
        for rotation in range(16):
            if not imm & ~0xFF:
                return (rotation << 8) | imm
            imm = (imm << 2 | imm >> 30) & 0xFFFFFFFF
        self.valid = False
        return 0

    def validate(self, m_bytes):
        if self.add_imm is None:
            return True
        m_val = int.from_bytes(m_bytes, "little")
        return m_val >> 0x34 == 0xE59 and self.ldr_imm == m_val >> 0x20 & 0xFFF


class Instruct64(Instruct):
    def immediates(self):
        ppo = int(self.pp_offset, 16)
        if ppo % 8:
            self.valid = False
        if ppo // 8 >> 0xC:
            self.add_imm = (ppo & ~0xFFF) >> 0xC
            self.add_imm2 = ppo & 0xFFF
            self.ldr_imm = (ppo & 0xFFF) >> 3
        else:
            self.ldr_imm = ppo >> 3

    def pattern(self, reg):
        if self.add_imm is None:
            ldr_bytes = (
                ((((0x3E5000 | self.ldr_imm) << 5) | 0x1B) << 5) | reg
            ).to_bytes(4, "little")
            return compile(escape(ldr_bytes))
        add_bytes = (
            ((((0x245000 | self.add_imm) << 5) | 0x1B) << 5) | reg
        ).to_bytes(4, "little")
        return compile(escape(add_bytes) + b"(?s:...)[\xf9\xfd\xbd\x7d\x3d\x91]")

    def validate(self, m_bytes):
        if self.add_imm is None:
            return True
        m_val = int.from_bytes(m_bytes, "little")
        imm = m_val >> 0x2A & 0xFFF
        shift = m_val >> 0x36
        return (
            shift in (0x3E5, 0x3F5)
            and self.ldr_imm == imm
            or shift == 0x2F5
            and self.ldr_imm << 1 == imm
            or shift == 0x1F5
            and self.ldr_imm << 2 == imm
            or shift == 0xF5
            and self.ldr_imm << 3 == imm
            or shift == 0xF7
            and self.ldr_imm >> 1 == imm
            or shift == 0x244
            and self.add_imm2 == imm
        )


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
                    + "pp+"
                    + instruct.pp_offset
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
                                + match.function
                                + self.color.addr
                                + "  "
                                + match.address
                                + self.color.ofs
                                + "  "
                                + hex(int(match.address, 16) - int(match.function, 16))
                                + "\n"
                                if match.function is not None
                                else self.color.addr + match.address + "\n"
                            )
                            r += (
                                "･"
                                + str(i)
                                + (3 - int(log(i, 10))) * " "
                                + addresses
                                + self.color.rst
                            )
                            r += self.disass(match.assembly) if not self.addr_only else ""
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
        if self.matches():
            return dumps(self.matches(), indent=2)
        return ""

    def matches(self):
        matches = {}
        self.search()
        if self.instruct_list:
            for instruct in self.instruct_list:
                if instruct.valid:
                    if instruct.match_list:
                        matches[instruct.pp_offset] = [
                            match._replace(
                                assembly=" ".join(findall("..", match.assembly.hex().upper()))
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
                with open(self.libapp, "rb") as file_obj:
                    with mmap(file_obj.fileno(), length=0, access=1) as mmap_obj:
                        self.set_elf_class(mmap_obj)
                        self.search_instr(mmap_obj)
            else:
                print("pptool: error: libapp is not set")
        else:
            print("pptool: error: offset list is required")

    def search_instr(self, mmap_obj):
        if self.elf_class:
            invalid = self.validate_offsets()
            if invalid is None:
                self.populate_instruct_list(mmap_obj)
            else:
                print(
                    "pptool: error: argument offset: invalid offset value: '{}'".format(
                        invalid
                    )
                )
        else:
            print("pptool: error: argument libapp: unsupported file")

    def set_elf_class(self, mmap_obj):
        header = int.from_bytes(mmap_obj[0:5], "little")
        if header in (0x1464C457F, 0x2464C457F) and mmap_obj[18:20] in (
            b"(\x00",
            b"\xb7\x00",
        ):
            self.elf_class = header >> 0x20

    def set_libapp(self, libapp):
        self.libapp = None
        self.offsets = None
        self.instruct_list = None
        try:
            if os_path.isfile(libapp):
                self.libapp = libapp
            else:
                print("pptool: error: invalid path value: '{}'".format(libapp))
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
                        print("pptool: error: invalid offset value: {}".format(ppo))
                        return
                except ValueError:
                    print("pptool: error: invalid offset value: {}".format(ppo))
                    return
                except TypeError:
                    print("pptool: error: invalid offset type: {}".format(type(ppo)))
                    return
            self.offsets = sorted(
                list(set(offs.lower() for offs in ppo_seq)),
                key=lambda ppoffset: int(ppoffset, 16),
            )

    def simple(self):
        out = ""
        addresses = self.addresses()
        if addresses:
            out += "PP+offset Addresses"
            for ofs in addresses:
                line = "\n" + 10 * " "
                address = addresses[ofs]
                if address:
                    out += "\n{}:{}{}".format(ofs, line, line.join(address))
        return out

    def validate_offsets(self):
        for offset in self.offsets:
            if isinstance(offset, str):
                try:
                    o_int = int(offset, 16)
                    if self.elf_class == 2 and (o_int < 0x10 or o_int > 0xFFFFFF):
                        return offset
                    if self.elf_class == 1 and (o_int < 0x7 or o_int > 0xFFFFF):
                        return offset
                except ValueError:
                    return None
        return None


def validate_path(string):
    if os_path.isfile(string):
        return string
    raise ValueError


def validate_offset(pp_offset):
    try:
        ppo = int(pp_offset, 16)
        if ppo > 0:
            return pp_offset
        raise ValueError
    except Exception as exc:
        raise ValueError from exc


def main():
    parser = argparse.ArgumentParser(
        description=(
            "PPTool finds the loading addresses of Dart objects in libapp.so\nthrough"
            " their pool pointer offset.\nARM64, ARM libs supported. Runs on Debian 11"
            " amd64/x64.\n\n"
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("-v", "--version", action="version", version="2.0")
    parser.add_argument("-c", action="store_false", help="use default color")
    parser.add_argument("-d", action="store_true", help="don't display assembly/disassembly")
    parser.add_argument("-s", action="store_true", help="create a simple output")
    parser.add_argument("-j", action="store_true", help="full output in JSON format")
    parser.add_argument("libapp", help="path to libapp.so", type=validate_path)
    parser.add_argument(
        "offset",
        nargs="+",
        help=(
            "specify pool pointer offsets to be searched\nsequence of hex strings   "
            " \narm:   0x6 < offset < 0x100000  ; offset mod 4 = 3    \narm64: 0xf <"
            " offset < 0x1000000 ; offset mod 8 = 0"
        ),
        type=validate_offset,
    )
    args = parser.parse_args()
    ppt = PPTool()
    ppt.set_libapp(args.libapp)
    ppt.set_offsets(args.offset)
    if args.j:
        print(ppt.json())
    elif args.s:
        print(ppt.simple())
    else:
        print(ppt.result(args.c, args.d))


if __name__ == "__main__":
    main()
