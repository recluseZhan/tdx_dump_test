savedcmd_/home/hjxzhan/tdx_dump_test/page1.ko := ld -r -m elf_x86_64 -z noexecstack --build-id=sha1  -T scripts/module.lds -o /home/hjxzhan/tdx_dump_test/page1.ko /home/hjxzhan/tdx_dump_test/page1.o /home/hjxzhan/tdx_dump_test/page1.mod.o;  make -f ./arch/x86/Makefile.postlink /home/hjxzhan/tdx_dump_test/page1.ko
