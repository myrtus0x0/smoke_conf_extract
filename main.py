import argparse
import collections
import hashlib
import json
import logging
import math
import struct
import sys

import malduck
import pefile
import structlog
import unicorn

import conf_extract
import deobfuscation
import unicorn_pe_loader


def estimate_shannon_entropy(dna_sequence):
    m = len(dna_sequence)
    bases = collections.Counter([tmp_base for tmp_base in dna_sequence])
 
    shannon_entropy_value = 0
    for base in bases:
        n_i = bases[base]
        p_i = n_i / float(m)
        entropy_i = p_i * (math.log(p_i, 2))
        shannon_entropy_value += entropy_i
 
    return shannon_entropy_value * -1

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


def emulate_decompress_call(emulator:unicorn_pe_loader.InitUnicorn, start_func, end_func, compressed_data, decompressed_size):
    logger = structlog.get_logger(__name__)
    
    logger.info("starting emulation", start_addr="0x%x" % start_func, end_func="0x%x" % end_func)
    
    # reset stack
    logger.info("setting stack and regs")
    emulator.create_stack()

    decompressed_addr = 0x70000000

    # ensure our given section is unmapped at start
    try:
        emulator.mu.mem_unmap(decompressed_addr, 32*1024)
    except:
        pass

    emulator.mu.mem_map(decompressed_addr, 32*1024)
    emulator.push_arg(decompressed_addr)
    
    # write our data to be decompressed
    compressed_addr = 0x80000000

    # ensure our given section is unmapped at start
    try:
        emulator.mu.mem_unmap(compressed_addr, 32*1024)
    except:
        pass

    emulator.mu.mem_map(compressed_addr, 32*1024)
    
    emulator.mu.mem_write(compressed_addr, compressed_data)
    emulator.push_arg(compressed_addr)
    
    emulator.push_arg(0)

    emulator.init_regs()

    try:
        emulator.mu.emu_start(start_func, end_func, timeout=120 * unicorn.UC_SECOND_SCALE)
    except unicorn.UcError as e:
        logger.error("error during emulation", error=e)
        decompressed_data = emulator.mu.mem_read(decompressed_addr, decompressed_size)
        return decompressed_data
    
    decompressed_data = emulator.mu.mem_read(decompressed_addr, decompressed_size)
    return decompressed_data


def decompress_buffer(emulator:unicorn_pe_loader.InitUnicorn, decrypted_stage_3):
    logger = structlog.get_logger(__name__)

    decompressed_size = struct.unpack("I", decrypted_stage_3[:4])[0]
    logger.info("decompressed info", decompressed_size="0x%x" % decompressed_size)
    
    decrypted_stage_3 = decrypted_stage_3[4:]
    start_func = 0x00401258
    end_func = 0x0040137E
    size_func = end_func - start_func
    logger.debug("func info", addr="0x%x" % start_func, size=size_func)
    return emulate_decompress_call(emulator, start_func, end_func, decrypted_stage_3, decompressed_size)


def deobfuscate_unpacked_smokeloader(sample_data:bytearray, emulator:unicorn_pe_loader.InitUnicorn, sample_path):
    pe_rep = pefile.PE(data=sample_data)

    opaque_predicate_info = deobfuscation.get_opaque_predicate_offsets(sample_data, pe_rep)
    cleaned_pe = deobfuscation.replace_ops(sample_data, opaque_predicate_info)
   
    patched_filename = sample_path.split(".")[0] + "_no_opaque_predicates.bin"
    with open(patched_filename, "wb") as f:
        f.write(cleaned_pe)
    
    cleaned_pe_rep = pefile.PE(data=cleaned_pe)
    
    # decrypt the function bodies
    decrypted_bodies_pe, xor_cookie = deobfuscation.bulk_decrypt_function_bodies(cleaned_pe, patched_filename, emulator)
    if decrypted_bodies_pe is None:
        return None, None
    
    # remove another set of opaque predicates
    opaque_predicate_info = deobfuscation.get_opaque_predicate_offsets(decrypted_bodies_pe, cleaned_pe_rep)
    decrypted_bodies_pe = deobfuscation.replace_ops(decrypted_bodies_pe, opaque_predicate_info)

    return decrypted_bodies_pe, xor_cookie


def get_payloads_from_stage_2(sample_data:bytearray, emulator:unicorn_pe_loader.InitUnicorn, xored_pe):
    # xored_pe is the entire PE file XOR crypted with the single byte key. This ensures all the function bodies 
    # are decrypted and we can identify the offsets
    logger = structlog.get_logger(__name__)

    payload_details = conf_extract.extract_offsets_size_stage_2(sample_data)
    payload_details += conf_extract.extract_offsets_size_stage_2(xored_pe)

    payloads = []
    for payload in payload_details:
        offset = payload[0] + 0x400000
        size = payload[1]
        try:
            payload = emulator.get_bytes(offset, size)
        except:
            logger.error("unable to get payload", rva="0x%x" % offset)
            continue
        
        entropy_payload = estimate_shannon_entropy(payload)
        if entropy_payload < 7.9:
            logger.error("data most likely isn't our payload", offset="0x%x" % offset, size="0x%x" % size, entropy="%lf" % entropy_payload)
            continue
        logger.info("payload info", offset="0x%x" % offset, size="0x%x" % size, entropy="%lf" % entropy_payload)
        payloads.append(payload)

    return payloads


parser = argparse.ArgumentParser(description='Smoke Conf Extract')
parser.add_argument('--json', action='store_true')
parser.add_argument('sample')


def main():
    logger = structlog.get_logger(__name__)
    init_logger() 

    args = parser.parse_args()

    with open(args.sample, "rb") as f:
        smokeloader_unpacked_pe = f.read()
    
    emulator = unicorn_pe_loader.InitUnicorn(smokeloader_unpacked_pe, logger, args.sample, type_pe=True, bit=32, debug=False)

    deobfuscated_pe, xor_cookie = deobfuscate_unpacked_smokeloader(smokeloader_unpacked_pe, emulator, args.sample)
    if deobfuscated_pe is None:
        logger.error("unable to deobfuscate PE file")
        return 
    
    just_xored_pe = malduck.xor(xor_cookie & 0xFF, smokeloader_unpacked_pe)

    with open(args.sample + "_fully_deobfuscated.bin", "wb") as f:
        f.write(deobfuscated_pe)

    payloads = get_payloads_from_stage_2(deobfuscated_pe, emulator, just_xored_pe)
    if len(payloads) == 0:
        logger.error("unable to extract final stage")
        return

    with open("./decompression_sample.bin", "rb") as f:
        deocompress_client = f.read()
    decompress_emulator = unicorn_pe_loader.InitUnicorn(deocompress_client, logger, "./smokeloader_unpacked.bin", type_pe=True, bit=32, debug=False)

    for payload in payloads:
        logger.info("decrypting extracted PE with key", key="0x%x" % xor_cookie, len_pe=len(payload))
        decrypted_stage_3 = malduck.xor(xor_cookie.to_bytes(4, "little"), payload)

        decompressed_data = decompress_buffer(decompress_emulator, decrypted_stage_3)
        if decompressed_data is None:
            logger.error("unable to decompress data")
            return 
        
    
        stage_3_hash = hashlib.md5(decompressed_data).hexdigest()
        entropy = estimate_shannon_entropy(decompressed_data)
        if entropy < 5 or entropy > 7:
            logger.error("unable to decompress final stage", entropy=entropy, size="0x%x" % len(decompressed_data), hash_stage_3=stage_3_hash)
            continue
        logger.info("successfully decompressed stage 3", size="0x%x" % len(decompressed_data), hash_stage_3=stage_3_hash, new_entropy="%lf" % entropy)
    
        with open(stage_3_hash + ".bin", "wb") as f:
            f.write(decompressed_data)

        affiliate_id = conf_extract.extract_affiliate_id_from_stage_2(deobfuscated_pe)
        if affiliate_id is not None:
            logger.info("affiliate info", affiliate_id=affiliate_id)

        c2s = conf_extract.extract_c2_buffers(decompressed_data)
        for c2 in c2s:
            logger.info("c2 info", c2=c2)

        encrypt_keys = conf_extract.extract_encrypt_key(decompressed_data)
        decrypt_keys = conf_extract.extract_decrypt_key(decompressed_data)
        for decrypt_key in decrypt_keys:
            if decrypt_key in encrypt_keys:
                encrypt_keys.remove(decrypt_key)
        
        if len(encrypt_keys) == 1 and len(decrypt_keys) == 1:
            logger.info("RC4 keys", encrypt_key="0x%x" % encrypt_keys[0], decrypt_key="0x%x" % decrypt_keys[0])

        version = conf_extract.extract_version(decompressed_data)
        logger.info("version info", version=version)
        if len(c2s) > 0:
            config = json.dumps({
                "family": "smokeloader",
                "c2s": c2s,
                "networkEncryptionKey": "%x" % encrypt_keys[0],
                "networkDecryptionKey": "%x" % decrypt_keys[0],
                "affiliateID": affiliate_id,
                "version": version
            }, indent=" " * 4)
        
        break
    
    if args.json:
        print(config)


if __name__ == "__main__":
    main()
