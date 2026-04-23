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


from re import compile, escape


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
