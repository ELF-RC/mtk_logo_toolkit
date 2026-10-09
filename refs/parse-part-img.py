#!/usr/bin/env python
#
# MTK image parser for mkimg/part_hdr_t image lists.


from __future__ import print_function

import argparse
import os
import re
import struct
import sys


PART_MAGIC = 0x58881688
PART_HEADER_DEFAULT_ADDR = 0xFFFFFFFF
PART_HDR_SIZE = 512
CHUNK_SIZE = 1024 * 1024

PART_HDR_FORMAT = "<II32sIIIIIIIIII"


class ParseError(Exception):
    pass


def roundup(value, align):
    if align <= 0:
        raise ParseError("invalid align_sz: %d" % align)
    return (value + align - 1) & ~(align - 1)


def decode_name(raw_name):
    name = raw_name.split(b"\0", 1)[0]
    try:
        return name.decode("ascii")
    except UnicodeDecodeError:
        return name.decode("latin-1")


def sanitize_filename(name):
    name = name.strip()
    if not name:
        name = "unnamed"
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", name)
    name = name.rstrip(" .")
    return name or "unnamed"


class PartHdr(object):
    def __init__(self, values):
        self.magic = values[0]
        self.dsize = values[1]
        self.name = decode_name(values[2])
        self.maddr = values[3]
        self.mode = values[4]
        self.ext_magic = values[5]
        self.hdr_sz = values[6]
        self.hdr_ver = values[7]
        self.img_type = values[8]
        self.img_list_end = values[9]
        self.align_sz = values[10]
        self.dsize_extend = values[11]
        self.maddr_extend = values[12]

    @classmethod
    def parse(cls, data):
        if len(data) < PART_HDR_SIZE:
            raise ParseError("short part_hdr_t: got %d bytes" % len(data))
        values = struct.unpack_from(PART_HDR_FORMAT, data, 0)
        return cls(values)

    def is_fake_addr(self):
        return self.maddr == PART_HEADER_DEFAULT_ADDR

    def data_size(self):
        return self.dsize

    def align_size(self):
        return self.align_sz

    def padded_data_size(self):
        return roundup(self.data_size(), self.align_size())

    def next_offset(self, offset):
        return offset + PART_HDR_SIZE + self.padded_data_size()

    def fields(self):
        return (
            ("magic", self.magic),
            ("dsize", self.dsize),
            ("name", self.name),
            ("maddr", self.maddr),
            ("mode", self.mode),
            ("ext_magic", self.ext_magic),
            ("hdr_sz", self.hdr_sz),
            ("hdr_ver", self.hdr_ver),
            ("img_type", self.img_type),
            ("img_list_end", self.img_list_end),
            ("align_sz", self.align_sz),
            ("dsize_extend", self.dsize_extend),
            ("maddr_extend", self.maddr_extend),
        )


def fmt_value(name, value):
    if name == "name":
        return value
    text = "%u (0x%08x)" % (value, value)
    if name == "maddr" and value == PART_HEADER_DEFAULT_ADDR:
        text += " [fake addr]"
    return text


def read_hdr(fp, offset, file_size):
    if file_size - offset < PART_HDR_SIZE:
        raise ParseError(
            "offset 0x%x has only %d bytes left, smaller than part_hdr_t"
            % (offset, file_size - offset)
        )
    fp.seek(offset)
    data = fp.read(PART_HDR_SIZE)
    if len(data) != PART_HDR_SIZE:
        raise ParseError("failed to read part_hdr_t at offset 0x%x" % offset)
    return PartHdr.parse(data)


def iter_images(fp, file_size):
    offset = 0
    index = 0

    while offset < file_size:
        hdr = read_hdr(fp, offset, file_size)
        if hdr.magic != PART_MAGIC:
            raise ParseError(
                "header magic error at offset 0x%x: 0x%08x != 0x%08x"
                % (offset, hdr.magic, PART_MAGIC)
            )

        data_offset = offset + PART_HDR_SIZE
        data_end = data_offset + hdr.data_size()
        next_offset = hdr.next_offset(offset)
        if data_end > file_size:
            raise ParseError(
                "%s data exceeds file size: end=0x%x file=0x%x"
                % (hdr.name or ("image_%03d" % index), data_end, file_size)
            )
        if next_offset > file_size:
            raise ParseError(
                "%s padded image exceeds file size: next=0x%x file=0x%x"
                % (hdr.name or ("image_%03d" % index), next_offset, file_size)
            )

        yield index, offset, data_offset, next_offset, hdr

        index += 1
        offset = next_offset
        if hdr.img_list_end:
            break


def dump_headers(image_path):
    file_size = os.path.getsize(image_path)
    count = 0
    display_index = 0
    with open(image_path, "rb") as fp:
        for index, offset, data_offset, next_offset, hdr in iter_images(fp, file_size):
            # skip entries that were included as certs of previous image
            if hasattr(dump_headers, "skip_end") and offset < dump_headers.skip_end:
                continue
            print("[%03d] offset=0x%x data_offset=0x%x next_offset=0x%x" %
                (display_index, offset, data_offset, next_offset))
            print("  image_name   : %s" % hdr.name)
            print("  image_size   : %u (0x%x)" % (hdr.data_size(), hdr.data_size()))
            print("  load_addr    : %s" % fmt_value("maddr", hdr.maddr))
            print("  ---PART HDR---")
            # if hdr.is_fake_addr():
            #     print("  note         : maddr is 0xffffffff, part_load treats it as fake addr")
            for name, value in hdr.fields():
                print("  %-13s: %s" % (name, fmt_value(name, value)))
            print("  ---PART HDR---")
            print("  %-13s: %u (0x%x)" %
                  ("Padded Size", hdr.padded_data_size(), hdr.padded_data_size()))
            # detect following cert headers and print their fields under this image
            end_offset = next_offset
            try:
                next_hdr = read_hdr(fp, next_offset, file_size)
            except ParseError:
                next_hdr = None

            def is_cert_hdr(h):
                if not h:
                    return False
                n = (h.name or "").lower()
                return n.startswith("cert")

            certs = []
            if is_cert_hdr(next_hdr):
                next_hdr_end = next_hdr.next_offset(next_offset)
                certs.append((next_hdr, next_offset))
                end_offset = next_hdr_end
                try:
                    next2_hdr = read_hdr(fp, next_hdr_end, file_size)
                except ParseError:
                    next2_hdr = None
                if is_cert_hdr(next2_hdr):
                    certs.append((next2_hdr, next_hdr_end))
                    end_offset = next2_hdr.next_offset(next_hdr_end)

            if certs:
                for ci, (chdr, coff) in enumerate(certs, start=1):
                    cert_size = chdr.data_size()
                    print("  cert%d_name   : %s" % (ci, chdr.name))
                    print("    offset     : 0x%x" % coff)
                    print("    cert_size  : %u (0x%x)" % (cert_size, cert_size))
                    print("    load_addr  : %s" % fmt_value("maddr", chdr.maddr))
                    print("    paddedSize : %u (0x%x)" % (chdr.padded_data_size(), chdr.padded_data_size()))

                dump_headers.skip_end = end_offset
                count += 1
                display_index += 1
    print("total: %d sub-image(s)" % count)


def copy_range(src_fp, dst_path, offset, size):
    src_fp.seek(offset)
    remaining = size
    with open(dst_path, "wb") as dst_fp:
        while remaining:
            chunk = src_fp.read(min(CHUNK_SIZE, remaining))
            if not chunk:
                raise ParseError("unexpected EOF while writing %s" % dst_path)
            dst_fp.write(chunk)
            remaining -= len(chunk)


def split_images(image_path, out_dir, image_name):
    file_size = os.path.getsize(image_path)
    if out_dir is None:
        base = os.path.splitext(os.path.basename(image_path))[0]
        out_dir = base + "_split"
    if not os.path.isdir(out_dir):
        os.makedirs(out_dir)

    written = 0
    skip_end = 0
    with open(image_path, "rb") as fp:
        for index, offset, data_offset, next_offset, hdr in iter_images(fp, file_size):
            if offset < skip_end:
                # this header was already included as part of previous image (certs)
                continue
            if image_name is not None and hdr.name != image_name:
                continue

            # determine whether the next one or two headers are certs
            end_offset = next_offset
            try:
                # peek first following header
                next_hdr = read_hdr(fp, next_offset, file_size)
            except ParseError:
                next_hdr = None

            def is_cert_hdr(h):
                if not h:
                    return False
                n = (h.name or "").lower()
                return n.startswith("cert")

            if is_cert_hdr(next_hdr):
                next_hdr_end = next_hdr.next_offset(next_offset)
                end_offset = next_hdr_end
                # peek second following header
                try:
                    next2_hdr = read_hdr(fp, next_hdr_end, file_size)
                except ParseError:
                    next2_hdr = None
                if is_cert_hdr(next2_hdr):
                    end_offset = next2_hdr.next_offset(next_hdr_end)

            size = end_offset - offset
            filename = "%s.bin" % (sanitize_filename(hdr.name))
            out_path = os.path.join(out_dir, filename)
            if os.path.exists(out_path):
                raise ParseError("output file already exists: %s" % out_path)
            copy_range(fp, out_path, offset, size)
            print("%s: offset=0x%x size=%u image=%s load_addr=%s" %
                  (out_path, offset, size,
                   hdr.name, fmt_value("maddr", hdr.maddr)))
            written += 1
            skip_end = end_offset
    if image_name is not None and written == 0:
        raise ParseError("image not found: %s" % image_name)
    print("wrote %d sub-image(s) to %s" % (written, out_dir))


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="MTK image parser: dump or split part_hdr_t image lists."
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--dump",
        action="store_true",
        help="print every sub-image part_hdr_t field",
    )
    mode.add_argument(
        "--split",
        action="store_true",
        help="split every sub-image with its part_hdr_t header kept",
    )
    parser.add_argument("image", help="input image file")
    parser.add_argument(
        "-o",
        "--out-dir",
        help="split output directory, default: <image_basename>_split",
    )
    parser.add_argument(
        "-n",
        "--name",
        help="only split sub-image with this exact name",
    )
    return parser.parse_args(argv)


def main(argv):
    args = parse_args(argv[1:])
    try:
        if args.dump:
            print("[DEBUG] Start Dump Image  headers --- "+args.image)
            dump_headers(args.image)
        else:
            print("[DEBUG] Start Split Images --- "+args.image)
            split_images(args.image, args.out_dir, args.name)
    except (IOError, OSError, ParseError) as err:
        print("error: %s" % err, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
