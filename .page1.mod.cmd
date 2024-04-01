cmd_/home/vjxzhan/tdx_dump_test/page1.mod := printf '%s\n'   page.o | awk '!x[$$0]++ { print("/home/vjxzhan/tdx_dump_test/"$$0) }' > /home/vjxzhan/tdx_dump_test/page1.mod
