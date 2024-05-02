import glob
import json
import struct

DEBUG = 0


UF2_MAGIC_START0 = 0x0A324655  # "UF2\n"
UF2_MAGIC_START1 = 0x9E5D5157  # Randomly selected
UF2_MAGIC_END    = 0x0AB16F30  # Ditto
FAMILY_ID        = 0xe48bff56  # RP2040
FS_START_ADDR    = 0x1012c000  # Pico W MicroPython LFSV2 offset

FLASH_START_ADDR = 0x10000000

BLOCK_SIZE = 512
DATA_SIZE = 256
HEADER_SIZE = 32
FOOTER_SIZE = 4
PADDING_SIZE = BLOCK_SIZE - DATA_SIZE - HEADER_SIZE - FOOTER_SIZE
DATA_PADDING = b"\x00" * PADDING_SIZE

BI_MAGIC = b'\xf2\xeb\x88\x71'
BI_END = b'\x90\xa3\x1a\xe7'

TYPE_RAW_DATA = 1
TYPE_SIZED_DATA = 2
TYPE_LIST_ZERO_TERMINATED = 3
TYPE_BSON = 4
TYPE_ID_AND_INT = 5
TYPE_ID_AND_STRING = 6

TYPE_BLOCK_DEVICE = 7
TYPE_PINS_WITH_FUNC = 8
TYPE_PINS_WITH_NAME = 9
TYPE_PINS_WITH_NAMES = 9
TYPE_NAMED_GROUP = 10

ID_PROGRAM_NAME = 0x02031c86
ID_PROGRAM_VERSION_STRING = 0x11a9bc3a
ID_PROGRAM_BUILD_DATE_STRING = 0x9da22254
ID_BINARY_END = 0x68f465de
ID_PROGRAM_URL = 0x1856239a
ID_PROGRAM_DESCRIPTION = 0xb6a07c19
ID_PROGRAM_FEATURE = 0xa1f4b453
ID_PROGRAM_BUILD_ATTRIBUTE = 0x4275f0d3
ID_SDK_VERSION = 0x5360b3ab
ID_PICO_BOARD = 0xb63cffbb
ID_BOOT2_NAME = 0x7f8882e1
ID_FILESYSTEM = 0x1009be7e

ID_MP_BUILTIN_MODULE = 0x4a99d719

IDS = {
    ID_PROGRAM_NAME: "Program Name",
    ID_PROGRAM_VERSION_STRING: "Program Version",
    ID_PROGRAM_BUILD_DATE_STRING: "Build Date",
    ID_BINARY_END: "Binary End Address",
    ID_PROGRAM_URL: "Program URL",
    ID_PROGRAM_DESCRIPTION: "Program Description",
    ID_PROGRAM_FEATURE: "Program Feature",
    ID_PROGRAM_BUILD_ATTRIBUTE: "Program Build Attribute",
    ID_SDK_VERSION: "SDK Version",
    ID_PICO_BOARD: "Pico Board",
    ID_BOOT2_NAME: "Boot Stage 2 Name"
}

TYPES = {
    TYPE_RAW_DATA: "Raw Data",
    TYPE_SIZED_DATA: "Sized Data",
    TYPE_LIST_ZERO_TERMINATED: "Zero Terminated List",
    TYPE_BSON: "BSON",
    TYPE_ID_AND_INT: "ID & Int",
    TYPE_ID_AND_STRING: "ID & Str",
    TYPE_BLOCK_DEVICE: "Block Device",
    TYPE_PINS_WITH_FUNC: "Pins With Func",
    TYPE_PINS_WITH_NAME: "Pins With Name",
    TYPE_PINS_WITH_NAMES: "Pins With Names",
    TYPE_NAMED_GROUP: "Named Group"
}

ALWAYS_A_LIST = ("NamedGroup", "BlockDevice", "ProgramFeature")


def addr_to_block(addr):
    return (addr - FLASH_START_ADDR) // DATA_SIZE


def block_to_addr(block):
    return (block * DATA_SIZE) + FLASH_START_ADDR


def uf2_to_bin(file, from_block = 0):
    file.seek(from_block * BLOCK_SIZE)
    while data := file.read(BLOCK_SIZE):
        start0, start1, flags, addr, size, block_no, num_blocks, family_id = struct.unpack(b"<IIIIIIII", data[:HEADER_SIZE])
        #print(f"Block {block_no}/{num_blocks} addr {addr:08x} size {size}")
        block_data = data[HEADER_SIZE:HEADER_SIZE + DATA_SIZE]
        yield addr, block_data


def get_blocks(file, from_block = 0, count = 1):
    uf2 = uf2_to_bin(file, from_block=from_block)
    _, block_data = next(uf2)
    try:
        for _ in range(count - 1):
            block_data += next(uf2)[1]
    except StopIteration:
        pass # EOF
    return block_data


def data_type_to_str(data_type):
    try:
        return TYPES[data_type]
    except KeyError:
        return "Unknown"


def data_id_to_str(data_id):
    try:
        return IDS[data_id]
    except KeyError:
        return "Unknown"


def is_valid_data_id(data_id):
    return data_id in IDS.keys()


def data_id_to_typename(data_id):
    return data_id_to_str(data_id).replace(" ", "")


def lookup_string(file, address):
    block = addr_to_block(address)
    offset = address - block_to_addr(block)
    data = get_blocks(file, from_block=block, count=4)[offset:]
    end = data.index(b"\x00")
    data = data[:end]
    return data.decode("utf-8")


def _parse_type_id_and_int(file, tag, block_data):
    data_id_maybe, data_value = struct.unpack("<II", block_data[:8])

    if DEBUG:
        print(f"{tag}: {data_id_to_str(data_id_maybe)} ({data_id_maybe:02x}) ({data_type_to_str(TYPE_ID_AND_INT)}): {data_value}")

    if is_valid_data_id(data_id_maybe):
        return data_id_to_typename(data_id_maybe), data_value
    else:
        return data_id_maybe, data_value


def _parse_type_id_and_str(file, tag, block_data):
    data_id_maybe, str_addr = struct.unpack("<II", block_data[:8])
    data_value = lookup_string(file, str_addr)

    if DEBUG:
        print(f"{tag}: {data_id_to_str(data_id_maybe)} ({data_id_maybe:02x}) ({data_type_to_str(TYPE_ID_AND_STRING)}): {data_value}")

    if is_valid_data_id(data_id_maybe):
        return data_id_to_typename(data_id_maybe), data_value
    else:
        return data_id_maybe, data_value


def _parse_block_device(file, tag, block_data):
    name_addr, start_addr, size, more_info_addr, flags = struct.unpack("<IIIIH", block_data[:18])
    name = lookup_string(file, name_addr)

    if DEBUG:
        print(f"{tag}: Block Device: {name} 0x{start_addr:04x} {size / 1024.0:0.2f}k")

    if more_info_addr:
        pass

    return "BlockDevice", {"name": name, "address": start_addr, "size": size, "flags": flags}


def _parse_named_group(file, tag, block_data):
    parent_id, flags, group_tag, group_id, label_addr = struct.unpack("<IHHII", block_data[:16])
    label = lookup_string(file, label_addr)

    return "NamedGroup", {"label": label, "parent": parent_id, "flags": flags, "tag": group_tag, "id": group_id}


entry_parsers = {
    TYPE_ID_AND_INT: _parse_type_id_and_int,
    TYPE_ID_AND_STRING: _parse_type_id_and_str,

    TYPE_BLOCK_DEVICE: _parse_block_device,

    TYPE_NAMED_GROUP: _parse_named_group,
}


def parse_entry(file, block_data, include_tags=("RP", "MP")):
    data_type, tag = struct.unpack("<H2s", block_data[:4])

    if tag.decode("utf-8") in include_tags:
        try:
            return entry_parsers[data_type](file, tag, block_data[4:])
        except KeyError:
            print(f"No parser found for: {data_type_to_str(data_type)}")



files = glob.glob("*.uf2")

for filename in files:
    file = open(filename, "rb")
    uf2 = uf2_to_bin(file)
    next(uf2) # Skip first block
    addr, block_data = next(uf2)

    try:
        start = block_data.index(BI_MAGIC) + 4
        end = block_data.index(BI_END)
    except ValueError:
        print(f"FAIL: {filename}")
        continue

    if DEBUG:
        print(f"FOUND: {filename}")
    entries_start, entries_end, mapping_table = struct.unpack("III", block_data[start:end])
    if DEBUG:
        print(f"{addr:04x} entries: {entries_start:04x} to {entries_end:04x}, mapping: {mapping_table:04x}")

    block_entries_start = addr_to_block(entries_start)
    block_entries_end = addr_to_block(entries_end)
    blocks_needed = block_entries_end - block_entries_start + 1
    if DEBUG:
        print(f"Entries cover blocks {block_entries_start} to {block_entries_end}")

    block_data = get_blocks(file, from_block=block_entries_start, count=blocks_needed)

    # Convert our start and end positiont to block relative
    entries_start -= block_to_addr(block_entries_start)
    entries_end -= block_to_addr(block_entries_start)
    entries_len = (entries_end - entries_start) // 4

    if DEBUG:
        print(f"Found {entries_len} entries from {entries_start} to {entries_end}...")

    entries = struct.unpack("I" * entries_len, block_data[entries_start:entries_end])

    if DEBUG:
        print(' '.join([f"{entry:04x}" for entry in entries]))

    parsed = {
        "FileName": filename,
        "FileType": "uf2"
    }

    for entry in entries:
        entry_block = addr_to_block(entry)
        entry_offset = entry - block_to_addr(entry_block)

        block_data = get_blocks(file, from_block=entry_block, count=2)[entry_offset:] # 1k ought to be enough?

        if DEBUG:
            print(f"Entry {entry:04x} should be in block {entry_block}, inspecting: {len(block_data)} bytes...")

        if (entry := parse_entry(file, block_data)) is not None:
            k, v = entry
            if k in parsed:
                if isinstance(parsed[k], list):
                    parsed[k] += [v]
                else:
                    parsed[k] = [parsed[k], v]
            else:
                # Coerce some things into a list, even if there's one entry,
                # so the output dict is predictable.
                parsed[k] = [v] if k in ALWAYS_A_LIST else v

    # Ugly hack to move data inside the respective named group...
    if "NamedGroup" in parsed:
        for group in parsed["NamedGroup"]:
            if group["id"] in parsed:
                group["data"] = parsed[group["id"]]
                del parsed[group["id"]]


    print(json.dumps(parsed, indent=4))