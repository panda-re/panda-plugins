# PANDA plugins

This repo is a prototype that builds PANDA's plugins out of tree.


## Download and Build
```bash
git clone https://github.com/panda-re/panda-plugins
cd panda3-plugins
git submodule update --init --recursive
mkdir build && cd build
cmake -G Ninja ..
ninja
```                                                                      

## Current Limitation

* It currently only supports `i386` and `x86_64` architecture. However, adding other architecture are possible and require some additional work (i.e, creating another macro similar to `macro(add_i386_plugin)` inside `Macros.cmake`). 

* It builds PANDA as a dependency (which I think may be fine, but I think it is possible we can link the plugins directory to an existing PANDA binary directory without having to spend a lot of time rebuilding it)

* It currently only supports plugins written in C/C++. For example, rust plugins currently cannot be build with this prototype, but I think we can use `ExternalProject_Add` to make it build with cmake. <https://stackoverflow.com/questions/31162438/how-can-i-build-rust-code-with-a-c-qt-cmake-project>
