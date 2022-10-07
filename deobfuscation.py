import sys
import re
import pefile
import pe_analysis
import structlog
import logging
import struct
import malduck


def get_opaque_predicate_offsets(data, pe_rep):
    logger = structlog.get_logger(__name__)

    smokeloader_regexs = [
        (
            rb"\x74(?P<compare_1>.)" # .text:00401151 74 07      jz      short loc_40115A ; Jump if Zero (ZF=1)
            rb"\x75(?P<compare_2>.)" # .text:00401153 75 05      jnz     short loc_40115A ; Jump if Not Zero (ZF=0)
        ),
        (
            rb"\x75(?P<compare_1>.)" # .text:00401177 75 06      jnz     short loc_40117F
            rb"\x74(?P<compare_2>.)" # .text:00401179 74 04      jz      short loc_40117F
        )
    ]

    offsets = []

    for pattern in smokeloader_regexs:
        matches = re.finditer(pattern, data, re.DOTALL)
        for match in matches:
            compare_1 = ord(match.group("compare_1"))
            compare_2 = ord(match.group("compare_2"))
            
            if compare_1 - compare_2 != 2:
                continue

            rva = pe_rep.OPTIONAL_HEADER.ImageBase + pe_rep.get_rva_from_offset(match.start())
            logger.info("opaque predicate found", rva="0x%x" % rva, first_comparison=compare_1, second_comparison=compare_2)
            offsets.append([match.start(), compare_1])
    
    return offsets

def get_args_from_decrypt_body_call(data):
    found_addr = get_code_offset_arg_from_decrypt_body_call(data)
    if found_addr is None:
        return None, None
    
    size = get_code_size_arg_from_decrypt_body_call(data, found_addr)
    if size is None:
        return None, None
    
    return found_addr, size

def get_code_offset_arg_from_decrypt_body_call(data):
    logger = structlog.get_logger(__name__)
    
    push_addr_patterns = [
        (
            rb"\x68(?P<offset_base_addr>.{4})"  # .text:00401264 68 92 12 00 00                          push    1292h
            rb"\x8b\x04\x24"                    # .text:00401269 8B 04 24                                mov     eax, [esp]
        ),
        (
            rb"\x68(?P<offset_base_addr>.{4})"  # .text:004011DC 68 05 12 00 00                          push    1205h
            rb"\x58"                            # .text:004011E1 58                                      pop     eax
        ),
        (
            rb"\xb8(?P<offset_base_addr>.{4})"  # .text:00401463 B8 8C 14 00 00                          mov     eax, 148Ch
        )
    ]

    for pattern in push_addr_patterns:
        matches = re.finditer(pattern, data)
        for match in matches:
            group_match = match.group("offset_base_addr")
            offset = struct.unpack("I", group_match)[0]
            if offset > 0xFFFF:
                continue
            
            logger.debug("offset", offset="0x%x" % offset)
            return offset


def get_code_size_arg_from_decrypt_body_call(data, address):
    logger = structlog.get_logger(__name__)
    
    push_size_patterns = [
        (
            rb"\x68(?P<size_data>.{4})"     # .text:0040213D 68 8A 00 00 00                          push    8Ah
            rb"\x59"                        # .text:00402142 59                                      pop     ecx
        ),
        (
            rb"\x6a(?P<size_data>.)"        # .text:004011F1 6A 4D                                   push    4Dh ; 'M'
        ),
        (
            rb"\x68(?P<size_data>.{4})"     # .text:0040127B 68 E5 00 00 00                          push    0E5h
            rb"\x8b\x0c\x24"                # .text:00401280 8B 0C 24                                mov     ecx, [esp+14h+var_14]
        ),
        (
            rb"\xb9(?P<size_data>.{4})"    # .text:0040182D B9 60 00 00 00                          mov     ecx, 60h ; '`'
        )
    ]

    for pattern in push_size_patterns:
        matches = re.finditer(pattern, data)
        for match in matches:
            group_match = match.group("size_data")
            
            # 1 byte push
            if len(group_match) == 1:
                size = ord(group_match)
                if size == address:
                    continue
                
                logger.debug("1 byte size", size="0x%x" % size)
                return size
            
            # 4 byte push
            elif len(group_match) == 4:
                size = struct.unpack("I", group_match)[0]
                if size == address or size > 0x1000:
                    continue

                logger.debug("4 byte size", size="0x%x" % size)
                return size

def replace_ops(data, opaque_predicate_info):
    for offset in opaque_predicate_info:
        file_offset = offset[0]
        jmp_distance = offset[1]
        num_bytes_to_nop = jmp_distance

        new_bytes = bytearray(b"\xEB")
        new_bytes.append(jmp_distance)
        for _ in range(num_bytes_to_nop):
            new_bytes.append(0x90)
        
        data = data[:file_offset] + new_bytes + data[file_offset+len(new_bytes):]
        
    return data

def find_body_decryptor(data):
     
    load_xor_operand_patterns = [
        (
            rb"\x68(?P<xor_cookie>.{4})"    #.text:00401165 68 FE 08 40 60                          push    604008FEh                   
            rb"\x5a"                        #.text:0040116A 5A                                    pop     edx
        ),
        (
            rb"\xba(?P<xor_cookie>.{4})"    # .text:00401291 BA 66 AE 71 47                          mov     edx, 4771AE66h
            rb"\xeb."                       # .text:00401296 EB 05                                   jmp     short loc_40129D
        )
    ]

    potential_decrypt_funcs = []

    for pattern in load_xor_operand_patterns:
        matches = re.finditer(pattern, data, re.DOTALL)
        for res in matches:
            body_decryptor = struct.unpack("I", res.group("xor_cookie"))[0]
            potential_decrypt_funcs.append((res.start(), body_decryptor))
    
    return potential_decrypt_funcs

def init_logger():
    renderer = structlog.dev.ConsoleRenderer()
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            renderer,
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.INFO)
    return

def get_func_body_decrypt_key(cleaned_pe):

    return 0xFE


def bulk_decrypt_function_bodies(cleaned_pe, patched_filename, emulator):
    logger = structlog.get_logger(__name__)

    hardcoded_calls = [
        0x401200,
        0x40128D,
        0x4013B0,
        0x401487,
        0x401839,
        0x4018DE,
        0x401AC8,
        0x401B50,
        0x401C59,
        0x401D6B,
        0x401E28,
        0x401EDF,
        0x40214A,
        0x402219,
        0x4024EC,
        0x4026C0,
        0x402750,
        0x40281C,
        0x4028AA,
    ]

    cleaned_pe_rep = pefile.PE(data=cleaned_pe)

    smokeloader_disas_rep = pe_analysis.PEAnalysis(patched_filename)

    potential_decrypt_funcs = find_body_decryptor(cleaned_pe)
    calls_to_decrypt_body = []
    correct_xor_cookie = 0

    for func_info in potential_decrypt_funcs:
        func_addr = func_info[0]
        xor_cookie = func_info[1]

        rva_body_decryptor = cleaned_pe_rep.OPTIONAL_HEADER.ImageBase + cleaned_pe_rep.get_rva_from_offset(func_addr)
        start_func, end_func = smokeloader_disas_rep.get_func_start_and_size_till_end(rva_body_decryptor)
        if start_func is None or end_func is None:
            logger.error("cant find start and end for rva", rva="0x%x" % rva_body_decryptor)
            logger.error("trying to find just start", rva="0x%x" % rva_body_decryptor)
            start_func = smokeloader_disas_rep.get_func_start(rva_body_decryptor)
            if start_func is None:
                return None, None
        
        logger.debug("decrypt body info", start="0x%x" % start_func, rva="0x%x" % rva_body_decryptor)

        calls_to_decrypt_body = smokeloader_disas_rep.get_xref_list(start_func)
        logger.info("calls recovered", n_calls=len(calls_to_decrypt_body))
        if len(calls_to_decrypt_body) > 8:
            correct_calls = calls_to_decrypt_body
            correct_xor_cookie = xor_cookie
            break
    
    if len(calls_to_decrypt_body) == 0 or correct_xor_cookie == 0:
        logger.error("cant find func decrypt call")
        return None, None
    
    logger.info("xor cookie", xor_key="0x%x" % correct_xor_cookie)

    decrypt_body_key = correct_xor_cookie & 0xFF
    size_window = 64
    for call in correct_calls:
        pre_call_window = emulator.get_bytes(call-size_window, size_window)
        rva_to_decrypt, size = get_args_from_decrypt_body_call(pre_call_window)
        if rva_to_decrypt is None or size is None:
            logger.error("unable to recover args", xref_offset="0x%x" % call)
            continue
        
        # adjust for base address
        rva_to_decrypt += 0x400000
        logger.info("decrypt function body call", key="0x%x" % decrypt_body_key, xref_offset="0x%x" % call, rva_to_decrypt_from="0x%x" % rva_to_decrypt, size_to_decrypt="0x%x" % size)

        data_to_decrypt = emulator.get_bytes(rva_to_decrypt, size)
        decrypted_body = malduck.xor(decrypt_body_key, data_to_decrypt)

        cleaned_pe = cleaned_pe.replace(data_to_decrypt, decrypted_body)

    return cleaned_pe, correct_xor_cookie

