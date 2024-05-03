import glob
import io
import json
import struct
import sys

DEBUG = False


UF2_MAGIC_START0 = 0x0A324655  # "UF2\n"
UF2_MAGIC_START1 = 0x9E5D5157  # Randomly selected
UF2_MAGIC_END    = 0x0AB16F30  # Ditto
FAMILY_ID        = 0xe48bff56  # RP2040
FS_START_ADDR    = 0x1012c000  # Pico W MicroPython LFSV2 offset

FLASH_START_ADDR = 0x10000000

BLOCK_SIZE   = 512
DATA_SIZE    = 256
HEADER_SIZE  = 32
FOOTER_SIZE  = 4
PADDING_SIZE = BLOCK_SIZE - DATA_SIZE - HEADER_SIZE - FOOTER_SIZE
DATA_PADDING = b"\x00" * PADDING_SIZE

BI_MAGIC = b"\xf2\xeb\x88\x71"
BI_END = b"\x90\xa3\x1a\xe7"

TYPE_RAW_DATA        = 1
TYPE_SIZED_DATA      = 2
TYPE_LIST_ZERO_TERMINATED = 3
TYPE_BSON            = 4
TYPE_ID_AND_INT      = 5
TYPE_ID_AND_STRING   = 6

TYPE_BLOCK_DEVICE    = 7
TYPE_PINS_WITH_FUNC  = 8
TYPE_PINS_WITH_NAME  = 9
TYPE_PINS_WITH_NAMES = 9
TYPE_NAMED_GROUP     = 10

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


class UF2Reader(io.BufferedReader):
    def __init__(self, filepath):
        bin = b"".join(self.uf2_to_bin(filepath))
        io.BufferedReader.__init__(self, io.BytesIO(bin))

    def uf2_to_bin(self, filepath):
        file = open(filepath, "rb")
        while data := file.read(BLOCK_SIZE):
            # start0, start1, flags, addr, size, block_no, num_blocks, family_id = struct.unpack(b"<IIIIIIII", data[:HEADER_SIZE])
            yield data[HEADER_SIZE:HEADER_SIZE + DATA_SIZE]


class PyDecl:
    def __init__(self, filepath, debug=False):
        self.entry_parsers = {
            TYPE_ID_AND_INT: self._parse_type_id_and_int,
            TYPE_ID_AND_STRING: self._parse_type_id_and_str,

            TYPE_BLOCK_DEVICE: self._parse_block_device,

            TYPE_NAMED_GROUP: self._parse_named_group,
        }

        self.file = UF2Reader(filepath)
        self.debug = debug

    def parse(self):
        self.file.seek(0)

        self.read_until(BI_MAGIC)

        data = self.read_until(BI_END)

        if len(data) != 12:
            sys.stderr.write(f"ERROR: Failed to parse {filename}\n")
            return None

        if DEBUG:
            print(f"FOUND: {filename}")

        entries_start, entries_end, mapping_table = struct.unpack("III", data)

        if DEBUG:
            print(f"entries: {entries_start:04x} to {entries_end:04x}, mapping: {mapping_table:04x}")

        # Convert our start and end positiont to block relative
        entries_start = self.addr_to_bin_offset(entries_start)
        entries_end = self.addr_to_bin_offset(entries_end)
        entries_bytes_len = entries_end - entries_start
        entries_len = entries_bytes_len // 4

        if DEBUG:
            print(f"Found {entries_len} entries from {entries_start} to {entries_end}, len {entries_bytes_len}...")

        self.file.seek(entries_start)
        data = self.file.read(entries_bytes_len)

        if len(data) != entries_bytes_len:
            sys.stderr.write(f"ERROR: Failed to parse {filename}\n")
            return None

        entries = struct.unpack("I" * entries_len, data)

        if DEBUG:
            print(" ".join([f"{entry:04x}" for entry in entries]))

        parsed = {}

        for entry in entries:
            entry_offset = self.addr_to_bin_offset(entry)

            self.file.seek(entry_offset)

            if DEBUG:
                print(f"Entry {entry:04x} should be at offset {entry_offset}...")

            if (entry := self.parse_entry()) is not None:
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

        return parsed

    def addr_to_bin_offset(self, addr):
        return addr - FLASH_START_ADDR

    def bin_offset_to_addr(self, offset):
        return offset + FLASH_START_ADDR

    def data_type_to_str(self, data_type):
        try:
            return TYPES[data_type]
        except KeyError:
            return "Unknown"

    def data_id_to_str(self, data_id):
        try:
            return IDS[data_id]
        except KeyError:
            return "Unknown"

    def is_valid_data_id(self, data_id):
        return data_id in IDS.keys()

    def data_id_to_typename(self, data_id):
        return self.data_id_to_str(data_id).replace(" ", "")

    def _read_until(self, delimiter=b"\x00"):
        while (chunk := self.file.read(len(delimiter))) != delimiter:
            yield chunk

    def read_until(self, delimiter=b"\x00"):
        return b"".join(self._read_until(delimiter))

    def lookup_string(self, address):
        offset = self.addr_to_bin_offset(address)
        self.file.seek(offset)
        data = self.read_until(delimiter=b"\x00")
        return data.decode("utf-8")

    def _parse_type_id_and_int(self, tag):
        data_id_maybe, data_value = struct.unpack("<II", self.file.read(8))

        if DEBUG:
            print(f"{tag}: {self.data_id_to_str(data_id_maybe)} ({data_id_maybe:02x}) ({self.data_type_to_str(TYPE_ID_AND_INT)}): {data_value}")

        if self.is_valid_data_id(data_id_maybe):
            return self.data_id_to_typename(data_id_maybe), data_value
        else:
            return data_id_maybe, data_value

    def _parse_type_id_and_str(self, tag):
        data_id_maybe, str_addr = struct.unpack("<II", self.file.read(8))
        data_value = self.lookup_string(str_addr)

        if DEBUG:
            print(f"{tag}: {self.data_id_to_str(data_id_maybe)} ({data_id_maybe:02x}) ({self.data_type_to_str(TYPE_ID_AND_STRING)}): {data_value}")

        if self.is_valid_data_id(data_id_maybe):
            return self.data_id_to_typename(data_id_maybe), data_value
        else:
            return data_id_maybe, data_value

    def _parse_block_device(self, tag):
        name_addr, start_addr, size, more_info_addr, flags = struct.unpack("<IIIIH", self.file.read(18))
        name = self.lookup_string(name_addr)

        if DEBUG:
            print(f"{tag}: Block Device: {name} 0x{start_addr:04x} {size / 1024.0:0.2f}k")

        if more_info_addr:
            pass

        return "BlockDevice", {"name": name, "address": start_addr, "size": size, "flags": flags}

    def _parse_named_group(self, tag):
        parent_id, flags, group_tag, group_id, label_addr = struct.unpack("<IHHII", self.file.read(16))
        label = self.lookup_string(label_addr)

        return "NamedGroup", {"label": label, "parent": parent_id, "flags": flags, "tag": group_tag, "id": group_id}

    def parse_entry(self, include_tags=("RP", "MP")):
        data_type, tag = struct.unpack("<H2s", self.file.read(4))

        if tag.decode("utf-8") in include_tags:
            try:
                return self.entry_parsers[data_type](tag)
            except KeyError:
                if self.debug:
                    sys.stderr.write(f"ERROR: No parser found for: {self.data_type_to_str(data_type)}\n")


if __name__ == "__main__":
    import argparse
    import pathlib

    def valid_file(file):
        file = pathlib.Path(file)
        if not file.exists():
            raise argparse.ArgumentTypeError(f"{file} does not exist!")
        return file if file.exists() else None

    parser = argparse.ArgumentParser()
    parser.add_argument("--verify", action="store_true", default=False, help="Perform basic verification.")
    parser.add_argument("--to-json", action="store_true", default=False, help="Output data as JSON.")
    parser.add_argument("files", type=valid_file, nargs="+", help="Files to parse.")
    args = parser.parse_args()

    validation_errors = False

    for filename in args.files:
        py_decl = PyDecl(filename)
        parsed = py_decl.parse()

        if parsed is not None:
            print(f"Processing: {filename}")

            if args.to_json:
                print(json.dumps(parsed, indent=4))

            if args.verify:
                binary_end = parsed.get("BinaryEndAddress", 0)
                block_devices = parsed.get("BlockDevice", [])
                for block_device in block_devices:
                    if (block_addr := block_device.get("address")) < binary_end:
                        sys.stderr.write("CRITICAL ERROR: Block device / binary overlap!\n")
                        sys.stderr.write(f"Binary ends at 0x{binary_end:04x}, block device starts at 0x{block_addr:04x}\n")
                        validation_errors = True

    sys.exit(1 if validation_errors else 0)
