cmd_/home/vjxzhan/tdx_dump_test/sha256_asm.o := gcc-11 -Wp,-MMD,/home/vjxzhan/tdx_dump_test/.sha256_asm.o.d -nostdinc -I./arch/x86/include -I./arch/x86/include/generated  -I./include -I./arch/x86/include/uapi -I./arch/x86/include/generated/uapi -I./include/uapi -I./include/generated/uapi -include ./include/linux/compiler-version.h -include ./include/linux/kconfig.h -I./ubuntu/include -D__KERNEL__ -fmacro-prefix-map=./= -D__ASSEMBLY__ -fno-PIE -m64 -DCC_USING_FENTRY -g -gdwarf-5  -DMODULE  -c -o /home/vjxzhan/tdx_dump_test/sha256_asm.o /home/vjxzhan/tdx_dump_test/sha256_asm.S  ; ./tools/objtool/objtool --hacks=jump_label --hacks=noinstr --hacks=skylake --retpoline --rethunk --sls --stackval --static-call --uaccess --prefix=16   --module /home/vjxzhan/tdx_dump_test/sha256_asm.o

source_/home/vjxzhan/tdx_dump_test/sha256_asm.o := /home/vjxzhan/tdx_dump_test/sha256_asm.S

deps_/home/vjxzhan/tdx_dump_test/sha256_asm.o := \
  include/linux/compiler-version.h \
    $(wildcard include/config/CC_VERSION_TEXT) \
  include/linux/kconfig.h \
    $(wildcard include/config/CPU_BIG_ENDIAN) \
    $(wildcard include/config/BOOGER) \
    $(wildcard include/config/FOO) \

/home/vjxzhan/tdx_dump_test/sha256_asm.o: $(deps_/home/vjxzhan/tdx_dump_test/sha256_asm.o)

$(deps_/home/vjxzhan/tdx_dump_test/sha256_asm.o):

/home/vjxzhan/tdx_dump_test/sha256_asm.o: $(wildcard ./tools/objtool/objtool)
