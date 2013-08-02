#!/bin/bash
base=$PWD
AMSOIL=$base/AMsoil
CHAPI=$base/chapi

if [ -d $AMSOIL ]; then
    echo "updating $AMSOIL"
    cd $AMSOIL
    git pull 
    cd $base
else
    echo "cloning into $AMSOIL"
    cd $base
    git clone https://github.com/fp7-ofelia/AMsoil.git
fi
cd $base

# link in chapi bits
if [ ! -d $AMSOIL/src/plugins/chrm ]; then
    ln -s $CHAPI/plugins/chrm $AMSOIL/src/plugins/chrm
fi
if [ ! -d $AMSOIL/src/plugins/marm ]; then
    ln -s $CHAPI/plugins/marm $AMSOIL/src/plugins/marm
fi
if [ ! -d $AMSOIL/src/plugins/chapiv1rpc ]; then
    ln -s $CHAPI/plugins/chapiv1rpc $AMSOIL/src/plugins/chapiv1rpc
fi

if [ ! -d $AMSOIL/src/tools ]; then
    ln -s $CHAPI/tools $AMSOIL/src/tools
fi
echo tools > $AMSOIL/src/.gitignore
