# py_decl

A Python parser for the Raspberry Pi binary declaration metadata.

Runs as a standalone parser tool, or as a library.

Runs on MicroPython for introspective debugging.

## CLI Usage

```
usage: py_decl.py [-h] [--verify] [--to-json] files [files ...]

positional arguments:
  files       Files to parse.

options:
  -h, --help  show this help message and exit
  --verify    Perform basic verification.
  --to-json   Output data as JSON.
```

eg:

```
./py_decl --to-json <uf2_or_bin_file>
```

## Library Usage

```python
from py_decl import PyDecl, UF2Reader

parser = PyDecl(UF2Reader(uf2_file_path))
print(parser.parse())
```

## TODO / Roadmap

See: https://github.com/Gadgetoid/py_decl/issues/1

## Special Thanks

* I would not have figured out this stuff without the README at https://github.com/rp-rs/rp-binary-info
* Or the binary structures detailed at https://github.com/raspberrypi/pico-sdk/blob/master/src/common/pico_binary_info/include/pico/binary_info/structure.h
