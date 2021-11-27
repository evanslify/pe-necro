@echo off
for %%i in ("C:\Users\es\Desktop\reloc-patch\*.dll") DO ( 

    echo %%i
    cd "C:\Program Files\IDA Pro 7.5"
    ida.exe -A -S"C:\Users\es\Desktop\ida-test.py" %%i
    cd "C:\Users\es\Desktop\reloc-patch\"
)

move *.dll \\vmware-host\Shared Folders\fdoemcd\ida-test\test-files\
move *.relocs.txt \\vmware-host\Shared Folders\fdoemcd\ida-test\test-files\