#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import idautils
import idaapi
import idc
import ida_funcs
import ida_ua
import ida_bytes
import ida_nalt
import ida_ida
import ida_auto
import ida_pro
import pefile


def is_in_original_range(addr):
    start = idaapi.get_imagebase()
    end = ida_ida.inf_get_max_ea()
    return start < addr and addr < end


class ForbiddenRangeFinder(object):

    def __init__(self, filename):
        self.pe = pefile.PE(filename)
        self.forbidden_area = [
            'IMAGE_DIRECTORY_ENTRY_EXPORT',
            'IMAGE_DIRECTORY_ENTRY_IMPORT',
            'IMAGE_DIRECTORY_ENTRY_RESOURCE',
            'IMAGE_DIRECTORY_ENTRY_EXCEPTION',
            'IMAGE_DIRECTORY_ENTRY_SECURITY',
            'IMAGE_DIRECTORY_ENTRY_BASERELOC',
            'IMAGE_DIRECTORY_ENTRY_DEBUG',
            'IMAGE_DIRECTORY_ENTRY_COPYRIGHT',
            'IMAGE_DIRECTORY_ENTRY_GLOBALPTR',
            'IMAGE_DIRECTORY_ENTRY_TLS',
            'IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG',
            'IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT',
            'IMAGE_DIRECTORY_ENTRY_IAT',
            'IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT',
            'IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR',
            'IMAGE_DIRECTORY_ENTRY_RESERVED'
        ]
        self.image_base = self.pe.OPTIONAL_HEADER.ImageBase

    def get_import_by_names(self):
        pe = self.pe
        bits = 64 if pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS else 32
        ordinal_flag = 2 ** (bits - 1)
        text_ranges = []
        for module in pe.DIRECTORY_ENTRY_IMPORT:
            ilt = pe.get_import_table(module.struct.OriginalFirstThunk)
            for i in range(len(ilt)):
                i = ilt[i]
                hint_rva = i.AddressOfData
                if hint_rva:
                    if hint_rva & ordinal_flag:
                        pass
                    else:
                        fun_name = pe.get_string_at_rva(
                            i.AddressOfData + 2,
                            pefile.MAX_IMPORT_NAME_LENGTH
                        )
                        if not pefile.is_valid_function_name(fun_name):
                            continue
                        else:
                            text_ranges.append((
                                self.image_base+i.AddressOfData,
                                self.image_base+i.AddressOfData+len(fun_name)
                            ))
                else:
                    raise Exception
        return text_ranges

    def get_ranges(self):
        result = []
        for forbidden_area in self.forbidden_area:
            zone = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY[forbidden_area]]
            if zone.Size and zone.VirtualAddress:
                forbidden_start = zone.VirtualAddress + self.image_base
                forbidden_end = zone.Size + forbidden_start
                result.append((forbidden_start, forbidden_end))
        result.extend(self.get_import_by_names())
        return result

    @staticmethod
    def is_in_range(addr, ranges):
        for i in ranges:
            start = i[0]
            end = i[1]
            if start < addr and addr < end:
                return True

    @staticmethod
    def filter_range(addrs, forbidden_range):
        return list(filter(lambda k: k not in forbidden_range, forbidden_range))


class MissingRangeFinder(object):

    def __init__(self, ranges, addr_start, addr_end):
        self.ranges = ranges
        self.addr_start = addr_start
        self.addr_end = addr_end

    def find_next_range(self, addr):
        # prev = None
        for i in self.ranges:
            if addr <= i[0]:
                self.ranges.remove(i)
                return i
            # prev = i

    def find_missing_ranges(self):
        done = False
        addr = self.addr_start
        gap_start_addr = None
        results = []
        while not done:
            next_range = self.find_next_range(addr)
            if not next_range:
                results.append((addr, self.addr_end))
                done = True
            else:
                gap_start_addr = addr
                gap_end_addr = next_range[0]
                if gap_start_addr != gap_end_addr:
                    results.append((gap_start_addr, gap_end_addr))
                addr = next_range[1]

        return results


class NonTextSegment(object):

    def __init__(self, *segs, forbid):
        self.segea = segs[0]
        self.forbid = forbid
        # self.segea = segea
        if len(segs) == 1:
            self.segend = idc.get_segm_end(self.segea)
        else:
            self.segend = segs[1]

    def is_entire_code(self):
        for head in idautils.Heads(self.segea, self.segend):
            flags = ida_bytes.get_flags(head)
            if ida_bytes.is_align(flags) or ida_bytes.get_bytes(head, 2) == b"\xcc\xcc":
                continue
            if not ida_bytes.is_code(flags):
                return False
        return True

    def seperate_code_data(self):
        codes = []
        datas = []
        prev_head = self.segea
        prev_status = None
        for head in idautils.Heads(self.segea, self.segend):
            flags = ida_bytes.get_flags(head)
            if ida_bytes.is_align(flags) or ida_bytes.get_byte(head) == 0xcc:
                continue
            if not prev_status:
                if ida_bytes.is_code(flags):
                    prev_status = 'code'
                else:
                    prev_status = 'data'
            if ida_bytes.is_code(flags):
                if prev_status == 'data':
                    # data->code
                    datas.append((prev_head, head))
                    prev_status = 'code'
                    prev_head = head
                else:
                    # code->code
                    continue
            else:
                if prev_status == 'code':
                    # code->data
                    codes.append((prev_head, head))
                    prev_status = 'data'
                    prev_head = head
                else:
                    # data->data
                    continue
        if prev_status == 'code':
            codes.append((prev_head, self.segend))
        else:
            datas.append((prev_head, self.segend))
        return (codes, datas)

    def _parse_before_first_head(self, start, end):
        addr = start
        result = []
        while True:
            if not ForbiddenRangeFinder.is_in_range(addr, self.forbid):
                data = int.from_bytes(
                    idc.get_bytes(addr, 0x4),
                    byteorder='little'
                )
                if is_in_original_range(data):
                    result.append(addr)
            addr += 0x4
            if addr >= self.segend:
                break
        return result

    def parse(self):
        result = []
        heads = list(idautils.Heads(self.segea, self.segend))
        if heads[0] != self.segea:
            result.extend(
                self._parse_before_first_head(
                    self.segea, heads[0]
                )
            )
        for idx, _addr in enumerate(heads):
            addr = _addr
            if not idx + 1 == len(heads):
                # check if len<4
                if heads[idx+1] - addr < 4:
                    # print("Skipping", hex(addr), "due to <4")
                    continue
                segend = heads[idx+1]
            else:
                segend = self.segend

            while True:
                # print("parse", hex(addr))
                if not ForbiddenRangeFinder.is_in_range(addr, self.forbid):
                    data = int.from_bytes(
                        idc.get_bytes(addr, 0x4),
                        byteorder='little'
                    )
                    if is_in_original_range(data):
                        result.append(addr)
                addr += 0x4
                if addr >= segend:
                    break
        return result


class TextSegment(object):

    def __init__(self, fname, forbid):
        self.forbid = forbid
        self.fname = fname
        self.relocs = []
        self.non_code_zones = []
        pass

    def parse_function(self, func_start, func_end):
        for head in idautils.Heads(func_start, func_end):
            inst = idautils.DecodeInstruction(head)
            if inst:
                for i in inst.ops:
                    if i.type == ida_ua.o_imm:
                        # mov x, <addr>
                        if is_in_original_range(i.value):
                            self.relocs.append(head + i.offb)
                            continue
                    elif i.type == ida_ua.o_mem:
                        # mov x, ds:<addr>
                        if is_in_original_range(i.addr):
                            self.relocs.append(head + i.offb)
                            continue
                    elif i.type == ida_ua.o_displ:
                        # mov x, byte ptr [x+x]
                        if is_in_original_range(i.addr):
                            self.relocs.append(head + i.offb)
                            continue

    def parse(self, segea):
        function_ranges = []
        for funcea in idautils.Functions(segea, idc.get_segm_end(segea)):
            func = ida_funcs.get_func(funcea)
            function_ranges.append((func.start_ea, func.end_ea))
            self.parse_function(func.start_ea, func.end_ea)
        finder = MissingRangeFinder(
            function_ranges, segea, idc.get_segm_end(segea))
        missing_ranges = finder.find_missing_ranges()

        for i in missing_ranges:
            # print('missing range', hex(i[0]), hex(i[1]))
            non_text_parser = NonTextSegment(i[0], i[1], forbid=self.forbid)
            if non_text_parser.is_entire_code():
                self.parse_function(i[0], i[1])
            else:
                codes, datas = non_text_parser.seperate_code_data()
                for code in codes:
                    # print('missing range - code', hex(i[0]), hex(i[1]))
                    # print('parse code', hex(i[0]), hex(i[1]))
                    self.parse_function(code[0], code[1])
                for data in datas:
                    # print('missing range - data', hex(i[0]), hex(i[1]))
                    # print('parse data', hex(i[0]), hex(i[1]))
                    _non_text_parser = NonTextSegment(data[0], data[1], forbid=self.forbid)
                    result = _non_text_parser.parse()
                    self.relocs += result
                    # print(len(result))
                    # print(len(self.relocs))
                    # if 0x40e85695 in self.relocs:
                    #     print('found wtf!')
                    # print(0x40)
                    # for i in result:
                    #     print(hex(i))
                    # print(len(self.relocs))
                # if seperated:
                #     code = seperated[0]
                #     data = seperated[1]
                #     self.parse_function(code[0], code[1])
                #     _non_text_parser = NonTextSegment(data[0], data[1], forbid=self.forbid)
                #     self.relocs += _non_text_parser.parse()

        return self.relocs


def run():

    ida_auto.auto_wait()
    all_result = []

    fname = ida_nalt.get_root_filename()
    forbidden_range_finder = ForbiddenRangeFinder(fname)
    forbidden_ranges = forbidden_range_finder.get_ranges()

    for segea in idautils.Segments():
        # print("scanning segment", idc.get_segm_name(segea))
        if idc.get_segm_name(segea) == '.text':
            parser = TextSegment(fname, forbidden_ranges)
            result = parser.parse(segea)
            all_result.extend(result)
            # print("text", len(result))
            # for i in result:
            #     print(hex(i))
        elif idc.get_segm_name(segea) == '.rsrc':
            continue
        else:
            # print("nontextseg", hex(segea))
            parser = NonTextSegment(segea, forbid=forbidden_ranges)
            result = parser.parse()
            all_result.extend(result)
            # for i in result:
            #     print(hex(i))
    # print("found {} relocs".format(len(all_result)))
    with open('.'.join(fname.split('.')[:-1]) + '.relocs.txt', "w") as f:
        f.writelines(["%s\n" % hex(i) for i in all_result])

    ida_pro.qexit(0)


if __name__ == '__main__':
    run()
