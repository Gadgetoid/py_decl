import sys
from py_decl import PyDecl, UF2Reader


if __name__ == "__main__":
    import argparse
    import pathlib

    def valid_file(suffixes):
        def _valid_file(file):
            file = pathlib.Path(file)
            if not file.exists():
                raise argparse.ArgumentTypeError(f"{file} does not exist!")
            if file.suffix.lower() not in suffixes:
                raise argparse.ArgumentTypeError(f"{file.suffix.lower()} format not supported!")
            return file if file.exists() else None
        return _valid_file

    parser = argparse.ArgumentParser()
    parser.add_argument("files", type=valid_file(('.uf2', '.bin')), nargs="+", help="Files to parse.")
    args = parser.parse_args()

    validation_errors = False

    labels = ["Filename", "Binary End", "Block Dev Start", "Binary Size", "Block Dev Size", "Usage"]
    print(" | ".join(labels))
    print("-|-".join(["-" * len(label) for label in labels]))

    for filename in args.files:
        py_decl = PyDecl(UF2Reader(filename) if filename.suffix.lower() == '.uf2' else open(filename, "rb"))
        parsed = py_decl.parse()

        if parsed is None:
            sys.stderr.write(f"ERROR: Failed to parse {filename}\n")
            continue

        binary_end = parsed.get("BinaryEndAddress", 0)
        binary_size = (binary_end & 0xFFFFFF) / 1024 / 1024
        block_devices = parsed.get("BlockDevice", [])
        for block_device in block_devices:
            block_addr = block_device.get("address")
            block_size = block_device.get("size") / 1024 / 1024
            bytes_remain = (block_addr - binary_end) / 1024

            if bytes_remain > 0:
                print(f"{filename.stem} | 0x{binary_end:04x} | 0x{block_addr:04x} | {binary_size:0.2f}M | {block_size:.2f}M | {bytes_remain:0.2f}K remaining")
            else:
                print(f"{filename.stem} | 0x{binary_end:04x} | 0x{block_addr:04x} | {binary_size:0.2f}M | {block_size:.2f}M | :warning: {bytes_remain:0.2f}K overlap!")
