cmd_Release/obj.target/multihashing/sha3/sph_luffa.o := cc '-DNODE_GYP_MODULE_NAME=multihashing' '-DUSING_UV_SHARED=1' '-DUSING_V8_SHARED=1' '-DV8_DEPRECATION_WARNINGS=1' '-D_LARGEFILE_SOURCE' '-D_FILE_OFFSET_BITS=64' '-DBUILDING_NODE_EXTENSION' -I/home/balderdash/.node-gyp/6.9.4/include/node -I/home/balderdash/.node-gyp/6.9.4/src -I/home/balderdash/.node-gyp/6.9.4/deps/uv/include -I/home/balderdash/.node-gyp/6.9.4/deps/v8/include -I../crypto  -fPIC -pthread -Wall -Wextra -Wno-unused-parameter -m64 -D_GNU_SOURCE -maes -fPIC -Ofast -flto -fuse-linker-plugin -funroll-loops -funswitch-loops -fpeel-loops -O3  -MMD -MF ./Release/.deps/Release/obj.target/multihashing/sha3/sph_luffa.o.d.raw   -c -o Release/obj.target/multihashing/sha3/sph_luffa.o ../sha3/sph_luffa.c
Release/obj.target/multihashing/sha3/sph_luffa.o: ../sha3/sph_luffa.c \
 ../sha3/sph_luffa.h ../sha3/sph_types.h
../sha3/sph_luffa.c:
../sha3/sph_luffa.h:
../sha3/sph_types.h:
