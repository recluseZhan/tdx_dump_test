cmd_/home/vjxzhan/tdx_dump_test/work1.mod := printf '%s\n'   work.o | awk '!x[$$0]++ { print("/home/vjxzhan/tdx_dump_test/"$$0) }' > /home/vjxzhan/tdx_dump_test/work1.mod
