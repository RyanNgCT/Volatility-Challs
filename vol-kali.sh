#!/usr/bin/bash

sudo apt-get install pcregrep libpcre++-dev python-dev

git clone https://github.com/gdabah/distorm.git
cd distorm3
sudo python setup.py install

sudo apt-get install yara -y

wget https://ftp.dlitz.net/pub/dlitz/crypto/pycrypto/pycrypto-2.6.1.tar.gz
tar -xvzf pycrypto-2.6.1.tar.gz
cd pycrypto-2.6.1
sudo python setup.py install

wget https://github.com/volatilityfoundation/volatility/archive/refs/tags/2.6.1.tar.gz
tar -xvzf 2.6.1.tar.gz
cd volatility-2.6.1
sudo python setup.py install
