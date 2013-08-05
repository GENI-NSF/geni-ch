#!/bin/bash
base=$PWD
GCF=$base/gcf

if [ -d $GCF ]; then
    echo "updating $GCF"
    cd $GCF
    git pull 
    cd $base
else
    echo "cloning into $GCF"
    cd $base
    git clone --depth 1 trac.gpolab.bbn.com:/srv/git/gcf.git
fi
cd $base

rm -rf $GCF/src/omnilib/frameworks/.gitignore
ln -s src/omnilib/frameworks/framework_chapi.py $GCF/src/omnilib/frameworks/framework_chapi.py 
echo framework_chapi.py >> $GCF/src/omnilib/frameworks/.gitignore
