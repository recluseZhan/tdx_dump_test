savedcmd_/home/hjxzhan/tdx_dump_test/dump_dev1.mod := printf '%s\n'   dump_dev.o | awk '!x[$$0]++ { print("/home/hjxzhan/tdx_dump_test/"$$0) }' > /home/hjxzhan/tdx_dump_test/dump_dev1.mod
