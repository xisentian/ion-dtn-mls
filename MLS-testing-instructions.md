#Quick Start
These are instructions to build and execute the directories and submodules required for testing MLS with BPSec

## Build Ion 
Build ION according to the instructions provided. To build the repository on a Mac, first run the intall_macos_sysctl.sh

```
 chmod u+x install_macos_sysctl.sh
 ./install_macos_sysctl.sh
 sudo ./install_macos_sysctl.sh
 autoreconf -fi
 ./configure
 sudo make install
 make test
```

# Build MLS
Build MLSpp according to the instructions from their repository (git@github.com:cisco/mlspp.git). We are using it as a git submodule so you may need to update it as needed.  

```
 git submodule update --init --recursive
 brew install nlohmann-json doctest build-essential
 make
 cd ..
 cd mlspp
 ./vcpkg/bootstrap-vcpkg.sh
```

You may also need to install catch2 if you encounter errors: 
`brew install catch2`

Verify the installation and test it: 

```
 make dev
 make test
 make install
 ./build/test/mlspp_test
 ./build/test/mlspp_test --list-tests
 ./build/test/mlspp_test "Two-Person Session Creation"
```

# Build MLS-BPSec test file 
```
./build_mls_inline.sh
```

# Run the MLS-BPSec tests 
```
./create_nodes.sh
./start_ion_nodes.sh
./run_mls_clients_tmux.sh
```
