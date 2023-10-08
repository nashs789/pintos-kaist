cd userprog
cd build
make clean
make
# pintos --fs-disk=10 -p tests/userprog/exit:exit -- -q -f run 'exit'
pintos --gdb --fs-disk=10 -p tests/userprog/fork-read:fork-read -- -q -f run 'fork-read'
# pintos --fs-disk=10 -p tests/userprog/args-single:args-single -- -q -f run 'args-single onearg'
# pintos --gdb --fs-disk=10 -p tests/userprog/args-single:args-single -- -q -f run 'args-single onearg'