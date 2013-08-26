#!/bin/bash
# Set up links from CHAPI plugins and tools into the AMSoil deployment
base=$PWD
AMSOIL=$base/AMsoil
CHAPI=$base

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

rm -f $AMSOIL/src/plugins/.gitignore
# hold off on marm for now
for pl in chrm chapiv1rpc sarm marm
do
    if [ ! -d $AMSOIL/src/plugins/$pl ]; then
	ln -s $CHAPI/plugins/$pl $AMSOIL/src/plugins/$pl
    fi
    echo $pl >> $AMSOIL/src/plugins/.gitignore
done

if [ ! -d $AMSOIL/src/tools ]; then
    ln -s $CHAPI/tools $AMSOIL/src/tools
fi
echo tools > $AMSOIL/src/.gitignore
