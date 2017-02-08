cmd_Release/obj.target/multihashing/boolberry.o := g++ '-DNODE_GYP_MODULE_NAME=multihashing' '-D_LARGEFILE_SOURCE' '-D_FILE_OFFSET_BITS=64' '-DBUILDING_NODE_EXTENSION' -I/usr/include/nodejs/include/node -I/usr/include/nodejs/src -I/usr/include/nodejs/deps/uv/include -I/usr/include/nodejs/deps/v8/include -I../crypto -I../node_modules/nan  -fPIC -pthread -Wall -Wextra -Wno-unused-parameter -m64 -D_GNU_SOURCE -maes -fPIC -Ofast -flto -fuse-linker-plugin -funroll-loops -funswitch-loops -fpeel-loops -O3 -ffunction-sections -fdata-sections -fno-rtti -fno-exceptions -std=gnu++0x -std=c++0x -maes -march=native -MMD -MF ./Release/.deps/Release/obj.target/multihashing/boolberry.o.d.raw   -c -o Release/obj.target/multihashing/boolberry.o ../boolberry.cc
Release/obj.target/multihashing/boolberry.o: ../boolberry.cc \
 ../boolberry.h ../crypto/cryptonote_core/cryptonote_format_utils.h \
 ../crypto/cryptonote_core/../hash.h \
 ../crypto/cryptonote_core/../hash-ops.h \
 ../crypto/cryptonote_core/../wild_keccak.h
../boolberry.cc:
../boolberry.h:
../crypto/cryptonote_core/cryptonote_format_utils.h:
../crypto/cryptonote_core/../hash.h:
../crypto/cryptonote_core/../hash-ops.h:
../crypto/cryptonote_core/../wild_keccak.h:
