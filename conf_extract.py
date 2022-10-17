import re
import struct
import sys
from contextlib import suppress

HAVE_MALDUCK = False
HAVE_PYCRYPTODOTMEX = False

with suppress(ImportError):
    import malduck
    HAVE_MALDUCK = True

with suppress(ImportError):
    from Crypto.Cipher import ARC4
    ARC4.key_size = range(1, 257)
    HAVE_PYCRYPTODOTMEX = True


import structlog

shellcode_base_addr = 0x10000C00


def extract_decrypt_key(stage_3_shellcode):
    decrypt_key_regex = (
        rb"\x8d.{3}"                                    # seg000:10001DCA 8D 54 24 44                             lea     edx, [esp+40h+rc4_key]
        rb"\xc7\x44\x24\x44(?P<decrypt_key>.{4})"       # seg000:10001DCE C7 44 24 44 BB 88 04 AA                 mov     [esp+40h+rc4_key], 0AA0488BBh
        rb"\x8B."                                       # seg000:10001DD6 8B CD                                   mov     ecx, ebp
        rb"\xE8.{3}"                                    # seg000:10001DD8 E8 FC 20 00 00                          call    rc4_crypt
    )

    keys = []

    results = re.finditer(decrypt_key_regex, stage_3_shellcode, re.DOTALL)

    for match in results:
        potential_key = struct.unpack("I", match.group("decrypt_key"))[0]
        keys.append(potential_key)

    return keys


def extract_encrypt_key(stage_3_shellcode):
    encrypt_key_regex = (
        rb"\xc7.{6}(?P<encrypt_key>.{4})" #         seg000:100034E0 C7 84 24 8C 00 00 00 D2 F0 F8 33   mov     [esp+7Ch+arg_C], 33F8F0D2h
        rb"\xe8.{4}"                      #         seg000:100034EB E8 E9 09 00 00                     call    rc4_crypt
    )

    keys = []

    results = re.finditer(encrypt_key_regex, stage_3_shellcode, re.DOTALL)

    for match in results:
        potential_key = struct.unpack("I", match.group("encrypt_key"))[0]
        keys.append(potential_key)

    return keys


def extract_c2_buffers(stage_3_shellcode):
    ptr_c2_list_regex = (
        rb"\x5e"                                        # seg000:100038A1 5E                                      pop     esi
        rb"\x8B\x14\x95(?P<c2_addr_index>.{4})"         # seg000:100038A2 8B 14 95 84 12 00 10                    mov     edx, ds:crypted_c2_list[edx*4]
        rb"\xe9.{4}"                                    # seg000:100038A9 E9 A3 04 00 00                          jmp     allocate_data_and_rc4_decrypt
    )

    c2s = []

    results = re.finditer(ptr_c2_list_regex, stage_3_shellcode, re.DOTALL)

    for match in results:
        addr_list = struct.unpack("I", match.group("c2_addr_index"))[0]
        addr_list = addr_list-shellcode_base_addr
        while True:
            c2_addr = stage_3_shellcode[addr_list:addr_list+4]
            if c2_addr == b"\x00\x00\x00\x00":
                break

            c2_addr = struct.unpack("I", c2_addr)[0] - shellcode_base_addr
            if c2_addr > len(stage_3_shellcode) - 4:
                break

            len_c2 = stage_3_shellcode[c2_addr]
            rc4_key = stage_3_shellcode[c2_addr+1:c2_addr+5]
            if HAVE_MALDUCK:
                c2 = malduck.rc4(rc4_key, stage_3_shellcode[c2_addr+5:c2_addr+5+len_c2]).decode("utf-8")
            elif HAVE_PYCRYPTODOTMEX:
                c2 = ARC4.new(rc4_key).decrypt(stage_3_shellcode[c2_addr+5:c2_addr+5+len_c2]).decode("utf-8")
            c2s.append(c2)

            addr_list += 4

    return c2s


def get_xor_cookie(sample_data:bytearray):
    decrypt_pe_regex = (
        rb"\xba(?P<xor_cookie>.{4})"    # .text:00401205 BA FE 08 40 60                          mov     edx, 604008FEh
        rb"\x8b.{2}"                    # .text:0040120A 8B 4D 0C                                mov     ecx, [ebp+size_crypted_data]
        rb"\x8b.{2}"                    # .text:0040120D 8B 75 08                                mov     esi, [ebp+arg_0]
        rb"\x89."                       # .text:00401210 89 F7                                   mov     edi, esi
        rb"\x51"                        # .text:00401212 51                                      push    ecx
    )

    xor_keys = []

    results = re.finditer(decrypt_pe_regex, sample_data, re.DOTALL)

    for match in results:
        xor_cookie = struct.unpack("I", match.group("xor_cookie"))[0]
        xor_keys.append(xor_cookie)

    return xor_keys


def extract_offsets_size_stage_2(sample_data:bytearray):
    # 66 8c e8 66 85 c0
    arch_check_regex = (
        rb"\x66\x8c\xe8" # .text:00402B26 66 8C E8                                mov     ax, gs
        rb"\x66\x85\xc0" # .text:00402B29 66 85 C0                                test    ax, ax
    )

    stage_3_regex = [
        (
            rb"\x8d.(?P<offset>.{4})"   # .text:00402B2E 8D 83 68 2F 00 00                       lea     eax, [ebx+2F68h]
            rb"\xb9(?P<size>.{4})"      # .text:00402B34 B9 9D 22 00 00                          mov     ecx, 229Dh
        ),
    ]

    payload_data = []

    logger = structlog.get_logger(__name__)

    matches = re.finditer(arch_check_regex, sample_data, re.DOTALL)
    for match in matches:
        windowed_data = sample_data[match.start():match.start()+0x100]

        logger.debug("arch check offset", start="0x%x" % match.start())

        for pattern in stage_3_regex:
            results = re.finditer(pattern, windowed_data, re.DOTALL)

            for match in results:
                offset_shellcode = struct.unpack("I", match.group("offset"))[0]
                if offset_shellcode > 0xFFFF:
                    continue

                size_shellcode = struct.unpack("I", match.group("size"))[0]
                if size_shellcode > 0xFFFF:
                    continue

                logger.debug("final stage location info", offset="0x%x" % offset_shellcode, size="0x%x" % size_shellcode)
                payload_data.append((offset_shellcode, size_shellcode))

    return payload_data


def extract_affiliate_id_from_stage_2(sample_data:bytearray):
    sample_length = len(sample_data)-1
    start_non_zero_data = 0
    for i in range(sample_length):
        current_byte = sample_data[sample_length-i]
        if current_byte != 0:
            start_non_zero_data = sample_length-i
            break
    try:
        affiliate_id = sample_data[start_non_zero_data-3:start_non_zero_data+1].decode("utf-8")
    except:
        affiliate_id = None

    return affiliate_id


def extract_version(sample_data:bytearray):
    version_compare = (
        rb"\xb8(?P<version>.{4})"   # seg000:0000127B B8 E6 07 00 00                          mov     eax, 7E6h
        rb"\x66.{3}"                # seg000:00001280 66 39 45 00                             cmp     [ebp+0], ax
        rb"\x0f.{5}"                # seg000:00001284 0F 85 96 03 00 00                       jnz     loc_1620
    )

    matches = re.finditer(version_compare, sample_data, re.DOTALL)
    for match in matches:
        version_year = struct.unpack("I", match.group("version"))[0]
        if version_year > 0xFFFF:
            continue

        return version_year

    return version_year


def main():
    with open(sys.argv[1], "rb") as f:
        smoke_stage_3 = f.read()

    c2s = extract_c2_buffers(smoke_stage_3)
    for c2 in c2s:
        print("c2: %s" % c2)
    encrypt_keys = extract_encrypt_key(smoke_stage_3)
    decrypt_keys = extract_decrypt_key(smoke_stage_3)
    for decrypt_key in decrypt_keys:
        if decrypt_key in encrypt_keys:
            encrypt_keys.remove(decrypt_key)

    if len(encrypt_keys) == 1 and len(decrypt_keys) == 1:
        print("encrypt key: 0x%x" % encrypt_keys[0])
        print("decrypt key: 0x%x" % decrypt_keys[0])



if __name__ == "__main__":
    main()
