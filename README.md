# PANDA plugins

This repo is a prototype that builds PANDA's plugins out of tree. This assumed that you have `libosi` already installed system wide. (Check out and build them [here](https://github.com/panda-re/libosi/tree/master))

## Download and Build
```bash
sudo apt update
sudo apt install -y libpcap0.8-dev libsqlite3-dev libdistorm3-dev libavro-dev
git clone https://github.com/panda-re/panda-plugins
cd panda3-plugins
ln -s /path/to/panda plugins/dependencies/panda/panda-wrapper 
mkdir build && cd build
cmake -G Ninja ..
ninja
```                                                                      

## Building the docker image

* To build:
```bash
cd /path/to/panda-plugins
sudo docker build -t panda-plugins .
```

* Example of running a plugin with docker
```bash
sudo docker run --rm -v `pwd`:/recordings panda-plugins panda-system-i386 -m 2048 -usbdevice tablet -replay /recordings/win7_32bit-calc -panda process_introspection -os "windows-32-7sp1"
```

