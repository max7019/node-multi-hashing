cmd_Release/obj.target/multihashing/shavite3.o := cc '-DNODE_GYP_MODULE_NAME=multihashing' '-D_LARGEFILE_SOURCE' '-D_FILE_OFFSET_BITS=64' '-DBUILDING_NODE_EXTENSION' -I/usr/include/nodejs/include/node -I/usr/include/nodejs/src -I/usr/include/nodejs/deps/uv/include -I/usr/include/nodejs/deps/v8/include -I../crypto -I../node_modules/nan  -fPIC -pthread -Wall -Wextra -Wno-unused-parameter -m64 -D_GNU_SOURCE -maes -fPIC -Ofast -flto -fuse-linker-plugin -funroll-loops -funswitch-loops -fpeel-loops -O3 -ffunction-sections -fdata-sections  -MMD -MF ./Release/.deps/Release/obj.target/multihashing/shavite3.o.d.raw  -c -o Release/obj.target/multihashing/shavite3.o ../shavite3.c
Release/obj.target/multihashing/shavite3.o: ../shavite3.c ../shavite3.h \
 ../sha3/sph_shavite.h ../sha3/sph_types.h
../shavite3.c:
../shavite3.h:
../sha3/sph_shavite.h:
../sha3/sph_types.h:
