# PENecro

This project is based on "Enabling dynamic analysis of Legacy Embedded Systems in full emulated environment", published on hardwear.io USA 2021 [1] and HITCON 2021 [2].

## Introduction

See slides [3].

## Prerequisites

This PoC is based on IDAPython, but using radare2 and similiar tools can achieve the same results.

## Usage

1. Extract PE from CE firmware
2. Remove all extra sections (e.g. debug) from PE
3. Use IDA in a way similiar to `go.bat` to create `n.dll.relocs.txt`
4. Use `write.py test.dll test.relocs.txt` to write relocs back to the PE
