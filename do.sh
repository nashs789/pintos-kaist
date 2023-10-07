cd userprog
cd build
make clean
make
# pintos --fs-disk=10 -p tests/userprog/exit:exit -- -q -f run 'exit'
pintos --fs-disk=10 -p tests/userprog/create-empty:create-empty -- -q -f run 'create-empty'
# pintos --fs-disk=10 -p tests/userprog/args-single:args-single -- -q -f run 'args-single onearg'
# pintos --gdb --fs-disk=10 -p tests/userprog/args-single:args-single -- -q -f run 'args-single onearg'