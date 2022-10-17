import collections
import struct

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from unicorn import (
    unicorn,
    Uc,
    UC_HOOK_CODE,
    UC_ARCH_X86,
    UC_MODE_32,
    UC_MODE_64,
    UC_HOOK_MEM_INVALID,
    UC_MEM_WRITE,
    UC_MEM_READ,
    UC_MEM_FETCH,
    UC_MEM_READ_UNMAPPED,
    UC_MEM_WRITE_UNMAPPED,
    UC_MEM_FETCH_UNMAPPED,
    UC_MEM_WRITE_PROT,
    UC_MEM_FETCH_PROT,
    UC_MEM_READ_AFTER,
)

IMAGE_FILE_MACHINE_I386 = 0x014C
IMAGE_FILE_MACHINE_AMD64 = 0x8664


class InitUnicorn(object):
    def __init__(self, data, logger, type_pe=False, bit=32, debug=False, data_addr=0xDEADBEEF00000000):
        self.logger = logger
        self.data_addr = data_addr
        self.data_size = 2 * 1024 * 1024
        self.code_base = 0x00400000
        self.DEBUG = debug
        self.is_stack_mapped = False
        self.md = Cs(CS_ARCH_X86, CS_MODE_32)

        self.is_x86_machine = False

        # pe check
        if type_pe:
            self.load_pe(data)
            if self.pe:
                self.init_unicorn()
                self.base = self.pe.OPTIONAL_HEADER.ImageBase
                self.map_pe_mem()
                self.create_stack()
                self.init_regs()
        else:
            if bit == 32:
                self.is_x86_machine = True
            else:
                self.is_x86_machine = False
            self.init_unicorn()
            self.map_data(data)
            self.create_stack()
        if self.DEBUG:
            self.add_debug()

    def init_regs(self, debug=False):
        if not debug:
            self.mu.reg_write(unicorn.x86_const.UC_X86_REG_EAX, self.data_addr)
            self.mu.reg_write(unicorn.x86_const.UC_X86_REG_EBX, self.data_addr)
            self.mu.reg_write(unicorn.x86_const.UC_X86_REG_ECX, self.data_addr)
            self.mu.reg_write(unicorn.x86_const.UC_X86_REG_EDX, self.data_addr)
            self.mu.reg_write(unicorn.x86_const.UC_X86_REG_ESI, self.data_addr)
            self.mu.reg_write(unicorn.x86_const.UC_X86_REG_EDI, self.data_addr)
            self.mu.reg_write(unicorn.x86_const.UC_X86_REG_R8, self.data_addr)
            self.mu.reg_write(unicorn.x86_const.UC_X86_REG_R9, self.data_addr)
            self.mu.reg_write(unicorn.x86_const.UC_X86_REG_R10, self.data_addr)
            self.mu.reg_write(unicorn.x86_const.UC_X86_REG_R11, self.data_addr)
            self.mu.reg_write(unicorn.x86_const.UC_X86_REG_R12, self.data_addr)
            self.mu.reg_write(unicorn.x86_const.UC_X86_REG_R13, self.data_addr)
            self.mu.reg_write(unicorn.x86_const.UC_X86_REG_R14, self.data_addr)
            self.mu.reg_write(unicorn.x86_const.UC_X86_REG_R15, self.data_addr)
        else:
            self.mu.reg_write(unicorn.x86_const.UC_X86_REG_EAX, 0xAAAAAAAAAAAAAAAA)
            self.mu.reg_write(unicorn.x86_const.UC_X86_REG_EBX, 0xBBBBBBBBBBBBBBBB)
            self.mu.reg_write(unicorn.x86_const.UC_X86_REG_ECX, 0xCCCCCCCCCCCCCCCC)
            self.mu.reg_write(unicorn.x86_const.UC_X86_REG_EDX, 0xDDDDDDDDDDDDDDDD)
            self.mu.reg_write(unicorn.x86_const.UC_X86_REG_ESI, 0xEEEEEEEEEEEEEEEE)
            self.mu.reg_write(unicorn.x86_const.UC_X86_REG_DI, 0xFFFFFFFFFFFFFFFF)
            self.mu.reg_write(unicorn.x86_const.UC_X86_REG_R8, 0xABABABABABABABAB)
            self.mu.reg_write(unicorn.x86_const.UC_X86_REG_R9, 0xBCBCBCBBCBCBCBCB)
            self.mu.reg_write(unicorn.x86_const.UC_X86_REG_R10, 0xCDCDCDCDCDCDCDCD)
            self.mu.reg_write(unicorn.x86_const.UC_X86_REG_R11, 0xDEDEDEDEDEDEDEDE)
            self.mu.reg_write(unicorn.x86_const.UC_X86_REG_R12, 0xDFDFDFDFDFDFDFDF)
            self.mu.reg_write(unicorn.x86_const.UC_X86_REG_R13, 0xACACACACACACACAC)
            self.mu.reg_write(unicorn.x86_const.UC_X86_REG_R14, 0xADADADADADADADAD)
            self.mu.reg_write(unicorn.x86_const.UC_X86_REG_R15, 0xAEAEAEAEAEAEAEAE)

    def set_ret_hook(self):
        self.ret_hook = self.mu.hook_add(UC_HOOK_CODE, self.hook_ret_code)

    def unset_ret_hook(self):
        self.mu.hook_del(self.ret_hook)

    def push_arg(self, val):
        esp = self.mu.reg_read(unicorn.x86_const.UC_X86_REG_ESP)
        self.mu.mem_write(esp - 4, struct.pack("<I", val))
        self.mu.reg_write(unicorn.x86_const.UC_X86_REG_ESP, esp - 4)

    def create_stack(self):
        if self.is_x86_machine:
            self.is_x86_machine = True
            self.stack_base = 0x00300000
            self.stack_size = 0x00100000
        else:
            self.is_x86_machine = False
            self.stack_base = 0xFFFFFFFF00000000
            self.stack_size = 0x0000000000100000

        if not self.is_stack_mapped:
            self.mu.mem_map(self.stack_base, self.stack_size)
            self.is_stack_mapped = True

        self.mu.mem_write(self.stack_base, b"\x00" * self.stack_size)
        if self.is_x86_machine:
            self.mu.reg_write(unicorn.x86_const.UC_X86_REG_ESP, self.stack_base + 0x800)
            self.mu.reg_write(unicorn.x86_const.UC_X86_REG_EBP, self.stack_base + 0x1000)
        else:
            self.mu.reg_write(unicorn.x86_const.UC_X86_REG_RSP, self.stack_base + 0x8000)
            self.mu.reg_write(unicorn.x86_const.UC_X86_REG_RBP, self.stack_base + 0x10000)

    def init_unicorn(self):
        if self.is_x86_machine:
            self.mu = Uc(UC_ARCH_X86, UC_MODE_32)
        else:
            self.mu = Uc(UC_ARCH_X86, UC_MODE_64)

    def map_data(self, data):
        self.mu.mem_map(self.code_base, 0x10000)
        self.mu.mem_write(self.code_base, data)

    def load_pe(self, pe_data):
        try:
            self.pe_raw = pe_data
            self.pe = pefile.PE(data=pe_data)
            if self.pe.FILE_HEADER.Machine == IMAGE_FILE_MACHINE_I386:
                self.is_x86_machine = True
            elif self.pe.FILE_HEADER.Machine == IMAGE_FILE_MACHINE_AMD64:
                self.is_x86_machine = False

        except Exception as e:
            self.pe = None
            if self.DEBUG:
                self.logger.error("pefile load error", error=e)
            return

    def prep_registers_for_c2(self):
        self.mu.reg_write(unicorn.x86_const.UC_X86_REG_RCX, self.data_addr)
        self.mu.reg_write(unicorn.x86_const.UC_X86_REG_RDX, self.data_addr + 4)
        return self.data_addr

    def clear_arbitrary_data_section(self):
        self.mu.mem_write(self.data_addr, b"\x00" * self.data_size)

    def clear_registers_for_c2(self):
        self.mu.mem_write(self.data_addr, b"\x00\x00\x00\x00")
        self.mu.mem_write(self.data_addr + 4, b"\x00\x00\x00\x00")

    def map_pe_mem(self):
        # data_mapping_size = required_mapping_size(data_size)
        data_address_start = self.data_addr
        self.mu.mem_map(data_address_start, self.data_size)
        # map executable memory
        align_size = self.pe.OPTIONAL_HEADER.SectionAlignment
        for section in self.get_map():
            self.mu.mem_map(section.va, self.align(section.size, align_size))
            temp_bytes = self.get_bytes(section.va, section.size)
            self.mu.mem_write(section.va, temp_bytes)

    def get_map(self):
        MapEntry = collections.namedtuple("MapEntry", ["va", "size"])
        ret = []
        for section in self.pe.sections:
            rva = section.VirtualAddress
            va = self.base + rva
            size = section.Misc_VirtualSize
            ret.append(MapEntry(va, size))
        return ret

    def get_bytes(self, va, length):
        rva = va - self.base
        return self.pe.get_data(rva, length)

    def va(self, rva):
        return self.base + rva

    def rva(self, va):
        return va - self.base

    def align(self, value, alignment):
        if value % alignment == 0:
            return value
        return value + (alignment - (value % alignment))

    def get_virtual_offset_from_physical(self, offset):
        return self.pe.get_rva_from_offset(offset) + self.pe.OPTIONAL_HEADER.ImageBase

    def add_debug(self):
        self.logger.info("adding debug hooks")
        self.mu.hook_add(UC_HOOK_CODE, self.hook_code)
        self.mu.hook_add(UC_HOOK_MEM_INVALID, self.hook_mem_invalid)

    def hook_ret_code(self, uc, address, size, user_data):
        for i in self.md.disasm(uc.mem_read(address, size), address):
            if i.mnemonic == "ret":
                uc.emu_stop()
        return

    def hook_code(self, uc, address, size, user_data):
        self.logger.info("Tracing instruction at 0x%x, instruction size = 0x%x" % (address, size))
        return

    def hook_call(self, uc, address, size, user_data):
        self.logger.info("Call instruction at 0x%x, instruction size = 0x%x" % (address, size))
        return

    def hook_mem_invalid(self, uc, access, address, size, value, user_data):
        eip = uc.reg_read(unicorn.x86_const.UC_X86_REG_EIP)
        if access == UC_MEM_WRITE:
            self.logger.error("invalid WRITE of 0x%x at 0x%X, data size = %u, data value = 0x%x" % (address, eip, size, value))
        elif access == UC_MEM_READ:
            self.logger.error("invalid READ of 0x%x at 0x%X, data size = %u" % (address, eip, size))
        elif access == UC_MEM_FETCH:
            self.logger.error("UC_MEM_FETCH of 0x%x at 0x%X, data size = %u" % (address, eip, size))
        elif access == UC_MEM_READ_UNMAPPED:
            self.logger.error("UC_MEM_READ_UNMAPPED of 0x%x at 0x%X, data size = %u" % (address, eip, size))
        elif access == UC_MEM_WRITE_UNMAPPED:
            self.logger.error("UC_MEM_WRITE_UNMAPPED of 0x%x at 0x%X, data size = %u" % (address, eip, size))
            size_map = 0x10000
            self.logger.info("mapping addr 0x%x (0x%x) to continue execution" % (address, size_map))
            self.key_addr = address
            uc.mem_map(address, size_map)
            return True
        elif access == UC_MEM_FETCH_UNMAPPED:
            self.logger.error("UC_MEM_FETCH_UNMAPPED of 0x%x at 0x%X, data size = %u" % (address, eip, size))
        elif access == UC_MEM_WRITE_PROT:
            self.logger.error("UC_MEM_WRITE_PROT of 0x%x at 0x%X, data size = %u" % (address, eip, size))
        elif access == UC_MEM_FETCH_PROT:
            self.logger.error("UC_MEM_FETCH_PROT of 0x%x at 0x%X, data size = %u" % (address, eip, size))
        elif access == UC_MEM_READ_AFTER:
            self.logger.error("UC_MEM_READ_AFTER of 0x%x at 0x%X, data size = %u" % (address, eip, size))
        return False
