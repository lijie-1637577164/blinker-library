#!/usr/bin/env python3
import argparse
import os
import re
import struct
import sys
from collections import OrderedDict
from datetime import datetime

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection


class ElfParser:
    def __init__(self, elf_path):
        self.elf_path = elf_path
        self.symbols = []
        self.sections = []
        self.arch = ""
        self.endian = ""
        self.entry_point = 0

    def parse(self):
        with open(self.elf_path, "rb") as f:
            elf = ELFFile(f)
            self.arch = elf.get_machine_arch()
            self.endian = elf.little_endian and "little" or "big"
            self.entry_point = elf.header["e_entry"]

            for section in elf.iter_sections():
                sec_info = {
                    "name": section.name,
                    "addr": section["sh_addr"],
                    "size": section["sh_size"],
                    "type": section["sh_type"],
                    "flags": section["sh_flags"],
                }
                self.sections.append(sec_info)

            for section in elf.iter_sections():
                if isinstance(section, SymbolTableSection):
                    for symbol in section.iter_symbols():
                        sym_info = self._extract_symbol(symbol, elf)
                        if sym_info:
                            self.symbols.append(sym_info)

        self._merge_with_map_symbols()

    def _extract_symbol(self, symbol, elf):
        name = symbol.name
        if not name:
            return None

        sym_type = symbol["st_info"]["type"]
        sym_bind = symbol["st_info"]["bind"]
        addr = symbol["st_value"]
        size = symbol["st_size"]

        if sym_type == "STT_NOTYPE" and addr == 0:
            return None
        if sym_type == "STT_FILE":
            return None
        if sym_type == "STT_SECTION":
            return None

        section_name = ""
        shndx = symbol["st_shndx"]
        if shndx != "SHN_UNDEF" and shndx != 0:
            try:
                sec = elf.get_section(shndx)
                section_name = sec.name
            except Exception:
                section_name = ""

        dwarf_type = self._get_dwarf_type(symbol, elf)

        category = self._classify_symbol(sym_type, sym_bind, size, section_name)

        return {
            "name": name,
            "address": addr,
            "size": size,
            "type": sym_type,
            "bind": sym_bind,
            "section": section_name,
            "dwarf_type": dwarf_type,
            "category": category,
        }

    def _get_dwarf_type(self, symbol, elf):
        try:
            dwarf_info = elf.get_dwarf_info()
            if dwarf_info is None:
                return ""
        except Exception:
            return ""
        return ""

    def _classify_symbol(self, sym_type, sym_bind, size, section_name):
        if size == 0:
            return "MEASUREMENT"

        is_writable = False
        if section_name:
            writable_sections = [".data", ".bss", ".noinit", ".heap", ".stack"]
            for wa in writable_sections:
                if wa in section_name:
                    is_writable = True
                    break

        if is_writable and size > 0:
            return "CHARACTERISTIC"
        else:
            return "MEASUREMENT"

    def _merge_with_map_symbols(self):
        pass

    def get_symbols(self):
        return self.symbols

    def get_sections(self):
        return self.sections

    def get_arch(self):
        return self.arch

    def get_endian(self):
        return self.endian

    def get_entry_point(self):
        return self.entry_point


class MapParser:
    def __init__(self, map_path):
        self.map_path = map_path
        self.symbols = []
        self.sections = []
        self.memory_regions = []
        self.raw_text = ""

    def parse(self):
        with open(self.map_path, "r", errors="ignore") as f:
            self.raw_text = f.read()

        self._detect_format()
        self._parse_memory_regions()
        self._parse_sections()
        self._parse_symbols()

    def _detect_format(self):
        if "Linker map from" in self.raw_text or "LOAD MODULE" in self.raw_text:
            self.format = "iar"
        elif "Memory Configuration" in self.raw_text or ".text" in self.raw_text:
            self.format = "gcc"
        elif "MAP OF" in self.raw_text.upper():
            self.format = "tasking"
        else:
            self.format = "gcc"

    def _parse_memory_regions(self):
        if self.format == "gcc":
            self._parse_gcc_memory_regions()
        elif self.format == "iar":
            self._parse_iar_memory_regions()
        else:
            self._parse_generic_memory_regions()

    def _parse_gcc_memory_regions(self):
        pattern = re.compile(
            r"^(\w+)\s+(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)", re.MULTILINE
        )
        for m in pattern.finditer(self.raw_text):
            name = m.group(1)
            origin = int(m.group(2), 16)
            length = int(m.group(3), 16)
            if origin > 0 and length > 0:
                self.memory_regions.append(
                    {"name": name, "origin": origin, "length": length}
                )

    def _parse_iar_memory_regions(self):
        pattern = re.compile(
            r"(\w+)\s+(?:code|ro\s+data|rw\s+data|zi\s+data)\s+memory\s+"
            r"(0x[0-9a-fA-F]+)\s+-\s+(0x[0-9a-fA-F]+)",
            re.IGNORECASE | re.MULTILINE,
        )
        for m in pattern.finditer(self.raw_text):
            name = m.group(1)
            start = int(m.group(2), 16)
            end = int(m.group(3), 16)
            self.memory_regions.append(
                {"name": name, "origin": start, "length": end - start}
            )

    def _parse_generic_memory_regions(self):
        pattern = re.compile(
            r"(0x[0-9a-fA-F]+)\s*[-–]\s*(0x[0-9a-fA-F]+)\s+(\w+)", re.MULTILINE
        )
        for m in pattern.finditer(self.raw_text):
            start = int(m.group(1), 16)
            end = int(m.group(2), 16)
            name = m.group(3)
            if end > start:
                self.memory_regions.append(
                    {"name": name, "origin": start, "length": end - start}
                )

    def _parse_sections(self):
        pattern = re.compile(
            r"^(\.\w+)\s+(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)", re.MULTILINE
        )
        for m in pattern.finditer(self.raw_text):
            name = m.group(1)
            addr = int(m.group(2), 16)
            size = int(m.group(3), 16)
            if addr > 0:
                self.sections.append({"name": name, "addr": addr, "size": size})

    def _parse_symbols(self):
        if self.format == "gcc":
            self._parse_gcc_symbols()
        elif self.format == "iar":
            self._parse_iar_symbols()
        else:
            self._parse_generic_symbols()

    def _parse_gcc_symbols(self):
        pattern = re.compile(
            r"^\s+(0x[0-9a-fA-F]+)\s+(\w+)", re.MULTILINE
        )
        for m in pattern.finditer(self.raw_text):
            addr = int(m.group(1), 16)
            name = m.group(2)
            if addr > 0 and not name.startswith(".") and not name.startswith("_"):
                self.symbols.append({"name": name, "address": addr})

    def _parse_iar_symbols(self):
        pattern = re.compile(
            r"(\w+)\s+(?:Abs|Rel)\s+(?:Place\s+in\s+)?(?:memory\s+)?"
            r"(?:segment\s+\w+\s+)?"
            r"(0x[0-9a-fA-F]+)",
            re.MULTILINE,
        )
        for m in pattern.finditer(self.raw_text):
            name = m.group(1)
            addr = int(m.group(2), 16)
            if addr > 0:
                self.symbols.append({"name": name, "address": addr})

    def _parse_generic_symbols(self):
        pattern = re.compile(r"(0x[0-9a-fA-F]+)\s+(\w+)", re.MULTILINE)
        for m in pattern.finditer(self.raw_text):
            addr = int(m.group(1), 16)
            name = m.group(2)
            if addr > 0 and not name.startswith("."):
                self.symbols.append({"name": name, "address": addr})

    def get_symbols(self):
        return self.symbols

    def get_sections(self):
        return self.sections

    def get_memory_regions(self):
        return self.memory_regions


class A2LGenerator:
    ELF_TYPE_MAP = {
        1: ("UBYTE", 1),
        2: ("UWORD", 2),
        4: ("ULONG", 4),
        8: ("AULONGLONG", 8),
    }

    SIGNED_TYPE_MAP = {
        1: ("SBYTE", 1),
        2: ("SWORD", 2),
        4: ("SLONG", 4),
        8: ("A_SLONGLONG", 8),
    }

    FLOAT_TYPES = {
        4: "FLOAT32",
        8: "FLOAT64",
    }

    def __init__(self, elf_parser, map_parser, output_path, project_name=None):
        self.elf = elf_parser
        self.map = map_parser
        self.output_path = output_path
        self.project_name = project_name or os.path.splitext(
            os.path.basename(self.elf.elf_path)
        )[0]
        self.measurements = []
        self.characteristics = []
        self.compu_methods = OrderedDict()
        self.record_layouts = OrderedDict()
        self._init_default_compu_methods()
        self._init_default_record_layouts()

    def _init_default_compu_methods(self):
        self.compu_methods["CM_NO_COMPU_METHOD"] = {
            "type": "IDENTICAL",
            "info": "No conversion",
        }
        self.compu_methods["CM_LINEAR"] = {
            "type": "LINEAR",
            "info": "Linear conversion y = x",
            "coeffs": [(1.0, 0.0)],
        }
        self.compu_methods["CM_DOUBLE"] = {
            "type": "LINEAR",
            "info": "Double conversion y = 2*x",
            "coeffs": [(2.0, 0.0)],
        }
        self.compu_methods["CM_HALVED"] = {
            "type": "LINEAR",
            "info": "Halved conversion y = 0.5*x",
            "coeffs": [(0.5, 0.0)],
        }

    def _init_default_record_layouts(self):
        for name, size in [
            ("RL_UBYTE", 1),
            ("RL_SBYTE", 1),
            ("RL_UWORD", 2),
            ("RL_SWORD", 2),
            ("RL_ULONG", 4),
            ("RL_SLONG", 4),
            ("RL_FLOAT32", 4),
            ("RL_FLOAT64", 8),
            ("RL_AULONGLONG", 8),
            ("RL_A_SLONGLONG", 8),
        ]:
            self.record_layouts[name] = {"size": size}

    def generate(self):
        elf_symbols = self.elf.get_symbols()
        map_symbols = self.map.get_symbols()
        map_sym_dict = {s["name"]: s["address"] for s in map_symbols}

        merged_symbols = OrderedDict()
        for sym in elf_symbols:
            name = sym["name"]
            if name in map_sym_dict:
                sym["address"] = map_sym_dict[name]
            merged_symbols[name] = sym

        for sym in map_symbols:
            name = sym["name"]
            if name not in merged_symbols:
                merged_symbols[name] = {
                    "name": name,
                    "address": sym["address"],
                    "size": 0,
                    "type": "STT_OBJECT",
                    "bind": "STB_GLOBAL",
                    "section": "",
                    "dwarf_type": "",
                    "category": "MEASUREMENT",
                }

        for name, sym in merged_symbols.items():
            if not self._is_valid_symbol(sym):
                continue

            size = sym["size"]
            if size == 0:
                size = self._guess_size(sym)

            category = sym["category"]
            compu_method = self._get_compu_method(sym, size)
            record_layout = self._get_record_layout(sym, size)

            if category == "MEASUREMENT":
                self.measurements.append(
                    {
                        "name": name,
                        "address": sym["address"],
                        "size": size,
                        "compu_method": compu_method,
                        "record_layout": record_layout,
                        "section": sym["section"],
                    }
                )
            elif category == "CHARACTERISTIC":
                self.characteristics.append(
                    {
                        "name": name,
                        "address": sym["address"],
                        "size": size,
                        "compu_method": compu_method,
                        "record_layout": record_layout,
                        "section": sym["section"],
                    }
                )

        self._write_a2l()

    def _is_valid_symbol(self, sym):
        name = sym["name"]
        if not name or len(name) < 2:
            return False
        if name.startswith("__"):
            return False
        if name.startswith("$"):
            return False
        if name.startswith("L."):
            return False
        if sym["address"] == 0:
            return False
        return True

    def _guess_size(self, sym):
        size = sym.get("size", 0)
        if size > 0:
            return size
        return 4

    def _get_compu_method(self, sym, size):
        return "CM_NO_COMPU_METHOD"

    def _get_record_layout(self, sym, size):
        dwarf_type = sym.get("dwarf_type", "")
        if dwarf_type:
            dwarf_lower = dwarf_type.lower()
            if "float" in dwarf_lower or "double" in dwarf_lower:
                if size in self.FLOAT_TYPES:
                    return f"RL_{self.FLOAT_TYPES[size]}"
            if "unsigned" in dwarf_lower or "uint" in dwarf_lower:
                if size in self.ELF_TYPE_MAP:
                    type_name, _ = self.ELF_TYPE_MAP[size]
                    return f"RL_{type_name}"
            if "signed" in dwarf_lower or "int" in dwarf_lower:
                if size in self.SIGNED_TYPE_MAP:
                    type_name, _ = self.SIGNED_TYPE_MAP[size]
                    return f"RL_{type_name}"

        if size in self.ELF_TYPE_MAP:
            type_name, _ = self.ELF_TYPE_MAP[size]
            return f"RL_{type_name}"
        if size in self.SIGNED_TYPE_MAP:
            type_name, _ = self.SIGNED_TYPE_MAP[size]
            return f"RL_{type_name}"
        return "RL_ULONG"

    def _write_a2l(self):
        lines = []
        lines.append('/* Generated by elf_map_to_a2l */')
        lines.append(f'/* Date: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} */')
        lines.append("")

        lines.append("ASAP2_VERSION 1 71")
        lines.append("BEGIN_PROJECT " + self._escape(self.project_name))
        lines.append("")

        lines.append(f'  "{self.project_name}"')
        lines.append("")

        lines.append("  BEGIN_MODULE " + self._escape(self.project_name))
        lines.append("")
        lines.append(f'    "{self.project_name}"')
        lines.append("")

        self._write_mod_par(lines)
        self._write_mod_common(lines)
        self._write_compu_methods(lines)
        self._write_record_layouts(lines)
        self._write_measurements(lines)
        self._write_characteristics(lines)

        lines.append("  END_MODULE")
        lines.append("")
        lines.append("END_PROJECT")
        lines.append("")

        with open(self.output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

    def _write_mod_par(self, lines):
        lines.append("    BEGIN_MOD_PAR")
        lines.append(f'      "{self.project_name} parameters"')
        lines.append("")

        lines.append(f"      VERSION \"{datetime.now().strftime('%Y%m%d_%H%M%S')}\"")
        lines.append("")

        addr_size = 4
        lines.append(f"      ADDR_EPK {addr_size}")
        lines.append("")

        for region in self.map.get_memory_regions():
            seg_name = self._escape(region["name"])
            addr = region["origin"]
            size = region["length"]
            lines.append(f"      BEGIN_MEMORY_SEGMENT {seg_name}")
            lines.append(f'        "{region["name"]} memory segment"')
            lines.append(f"        PRG_TYPE PRG_CODE")
            lines.append(f"        DATA_TYPE DTY_FLASH")
            lines.append(f"        ADDR_EPK 0x{addr:08X}")
            lines.append(f"        BEGIN_IF_DATA ADDRESS")
            lines.append(f"          0x{addr:08X}")
            lines.append(f"          0x{addr + size:08X}")
            lines.append(f"        END_IF_DATA")
            lines.append(f"      END_MEMORY_SEGMENT")
            lines.append("")

        for sec in self.map.get_sections():
            seg_name = self._escape(sec["name"].replace(".", "SEC_"))
            addr = sec["addr"]
            size = sec["size"]
            if addr > 0 and size > 0:
                lines.append(f"      BEGIN_MEMORY_SEGMENT {seg_name}")
                lines.append(f'        "{sec["name"]} section"')
                lines.append(f"        PRG_TYPE PRG_CODE")
                lines.append(f"        DATA_TYPE DTY_FLASH")
                lines.append(f"        BEGIN_IF_DATA ADDRESS")
                lines.append(f"          0x{addr:08X}")
                lines.append(f"          0x{addr + size:08X}")
                lines.append(f"        END_IF_DATA")
                lines.append(f"      END_MEMORY_SEGMENT")
                lines.append("")

        lines.append("    END_MOD_PAR")
        lines.append("")

    def _write_mod_common(self, lines):
        lines.append("    BEGIN_MOD_COMMON")
        lines.append(f'      "{self.project_name} common"')
        lines.append("")
        lines.append('      ALIGNMENT_BYTE 1')
        lines.append('      ALIGNMENT_WORD 2')
        lines.append('      ALIGNMENT_LONG 4')
        lines.append('      ALIGNMENT_FLOAT32 4')
        lines.append('      ALIGNMENT_FLOAT64 8')
        lines.append('      ALIGNMENT_INT64 8')
        lines.append('      ALIGNMENT_LONG64 8')
        lines.append("")

        arch = self.elf.get_arch()
        endian = self.elf.get_endian()
        byte_order = "LITTLE_ENDIAN" if endian == "little" else "BIG_ENDIAN"
        lines.append(f"      BYTE_ORDER {byte_order}")
        lines.append("")

        lines.append("    END_MOD_COMMON")
        lines.append("")

    def _write_compu_methods(self, lines):
        for cm_name, cm_info in self.compu_methods.items():
            lines.append(f"    BEGIN_COMPU_METHOD {self._escape(cm_name)}")
            lines.append(f'      "{cm_info["info"]}"')
            lines.append(f"      {cm_info['type']}")
            lines.append(f'      COMPU_TAB_REF "{cm_name}_TAB"')
            lines.append("")

            if cm_info["type"] == "LINEAR" and "coeffs" in cm_info:
                for factor, offset in cm_info["coeffs"]:
                    lines.append(f"      COEFFS {factor} {offset}")

            lines.append(f'      UNIT ""')
            lines.append(f"      FORMAT \"%.0\"")
            lines.append(f"    END_COMPU_METHOD")
            lines.append("")

    def _write_record_layouts(self, lines):
        for rl_name, rl_info in self.record_layouts.items():
            size = rl_info["size"]
            lines.append(f"    BEGIN_RECORD_LAYOUT {self._escape(rl_name)}")
            lines.append(f'      "{rl_name} record layout"')
            lines.append("")

            if size == 1:
                lines.append("      FNC_VALUES 1 UBYTE COLUMN_DIR DIRECT")
            elif size == 2:
                lines.append("      FNC_VALUES 1 UWORD COLUMN_DIR DIRECT")
            elif size == 4:
                if "FLOAT" in rl_name:
                    lines.append("      FNC_VALUES 1 FLOAT32 COLUMN_DIR DIRECT")
                else:
                    lines.append("      FNC_VALUES 1 ULONG COLUMN_DIR DIRECT")
            elif size == 8:
                if "FLOAT" in rl_name:
                    lines.append("      FNC_VALUES 1 FLOAT64 COLUMN_DIR DIRECT")
                else:
                    lines.append("      FNC_VALUES 1 A_ULONGLONG COLUMN_DIR DIRECT")

            lines.append("    END_RECORD_LAYOUT")
            lines.append("")

    def _write_measurements(self, lines):
        for meas in self.measurements:
            name = self._escape(meas["name"])
            long_id = f'"{meas["name"]} measurement"'
            compu_method = self._escape(meas["compu_method"])
            record_layout = self._escape(meas["record_layout"])
            addr = meas["address"]
            size = meas["size"]

            lines.append(f"    BEGIN_MEASUREMENT {name}")
            lines.append(f"      {long_id}")
            lines.append(f"      {compu_method}")
            lines.append(f"      0")
            lines.append(f"      READ")
            lines.append("")
            lines.append(f"      BEGIN_IF_DATA ECU_ADDRESS")
            lines.append(f"        0x{addr:08X}")
            lines.append(f"      END_IF_DATA")
            lines.append("")
            lines.append(f"      BEGIN_IF_DATA SYMBOL_TYPE")
            lines.append(f'        "{meas["section"]}"')
            lines.append(f"      END_IF_DATA")
            lines.append("")

            if size > 0:
                lines.append(f"      BEGIN_IF_DATA DATA_SIZE")
                lines.append(f"        {size}")
                lines.append(f"      END_IF_DATA")
                lines.append("")

            lines.append(f"    END_MEASUREMENT")
            lines.append("")

    def _write_characteristics(self, lines):
        for char in self.characteristics:
            name = self._escape(char["name"])
            long_id = f'"{char["name"]} characteristic"'
            compu_method = self._escape(char["compu_method"])
            record_layout = self._escape(char["record_layout"])
            addr = char["address"]
            size = char["size"]

            lines.append(f"    BEGIN_CHARACTERISTIC {name}")
            lines.append(f"      {long_id}")
            lines.append(f"      VALUE")
            lines.append(f"      0x{addr:08X}")
            lines.append(f"      {compu_method}")
            lines.append(f"      0")
            lines.append(f"      0")
            lines.append("")
            lines.append(f"      BEGIN_IF_DATA ECU_ADDRESS")
            lines.append(f"        0x{addr:08X}")
            lines.append(f"      END_IF_DATA")
            lines.append("")
            lines.append(f"      BEGIN_IF_DATA SYMBOL_TYPE")
            lines.append(f'        "{char["section"]}"')
            lines.append(f"      END_IF_DATA")
            lines.append("")

            if size > 0:
                lines.append(f"      BEGIN_IF_DATA DATA_SIZE")
                lines.append(f"        {size}")
                lines.append(f"      END_IF_DATA")
                lines.append("")

            lines.append(f"      RECORD_LAYOUT {record_layout}")
            lines.append("")
            lines.append(f"    END_CHARACTERISTIC")
            lines.append("")

    def _escape(self, name):
        name = re.sub(r"[^a-zA-Z0-9_]", "_", name)
        if name and name[0].isdigit():
            name = "_" + name
        return name


def main():
    parser = argparse.ArgumentParser(
        description="Generate A2L file from ELF and MAP files"
    )
    parser.add_argument("elf_file", help="Path to the ELF file")
    parser.add_argument("map_file", help="Path to the MAP file")
    parser.add_argument(
        "-o", "--output", default=None, help="Output A2L file path (default: <elf_name>.a2l)"
    )
    parser.add_argument(
        "-p", "--project", default=None, help="Project name for A2L header"
    )

    args = parser.parse_args()

    if not os.path.isfile(args.elf_file):
        print(f"Error: ELF file not found: {args.elf_file}", file=sys.stderr)
        sys.exit(1)
    if not os.path.isfile(args.map_file):
        print(f"Error: MAP file not found: {args.map_file}", file=sys.stderr)
        sys.exit(1)

    output_path = args.output
    if output_path is None:
        base = os.path.splitext(args.elf_file)[0]
        output_path = base + ".a2l"

    print(f"Parsing ELF file: {args.elf_file}")
    elf_parser = ElfParser(args.elf_file)
    elf_parser.parse()
    print(f"  Found {len(elf_parser.get_symbols())} symbols, "
          f"{len(elf_parser.get_sections())} sections")

    print(f"Parsing MAP file: {args.map_file}")
    map_parser = MapParser(args.map_file)
    map_parser.parse()
    print(f"  Found {len(map_parser.get_symbols())} symbols, "
          f"{len(map_parser.get_sections())} sections, "
          f"{len(map_parser.get_memory_regions())} memory regions")

    print(f"Generating A2L file: {output_path}")
    generator = A2LGenerator(elf_parser, map_parser, output_path, args.project)
    generator.generate()
    print(f"  Generated {len(generator.measurements)} MEASUREMENT entries")
    print(f"  Generated {len(generator.characteristics)} CHARACTERISTIC entries")
    print("Done.")


if __name__ == "__main__":
    main()
