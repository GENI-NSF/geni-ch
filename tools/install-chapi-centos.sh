#!/bin/bash

CHAPI_LOG_DIR=/var/log/geni-chapi

echoerr() { echo "$@" 1>&2; }

# Exit on error
set -e
# Echo commands with variables expanded
set -x

# Create the chapi log directory
if [ ! -d "${CHAPI_LOG_DIR}" ]; then
  sudo mkdir -p "${CHAPI_LOG_DIR}"
  sudo chown apache.apache "${CHAPI_LOG_DIR}"
fi

TMP_DIR=/tmp/chapi-install
if [ -x "${TMP_DIR}" ]; then
  echoerr "Temporary build directory ${TMP_DIR} exists."
  echoerr "Please remove it and run this script again."
  exit 1
fi

# Find out where this script lives. It should be in the
# "tools" directory of a chapi tree.
TOOLS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
CHAPI_DIR="${TOOLS_DIR}"/../../chapi

SHARE_DIR=/usr/share/geni-ch

# Make a directory for gcf to live in
if [ ! -d "${SHARE_DIR}" ]; then
  sudo /bin/mkdir -p "${SHARE_DIR}"
fi

mkdir "${TMP_DIR}"
cd "${TMP_DIR}"
mkdir chapi
cp -r "${CHAPI_DIR}" chapi
# Clean up any git cruft that got copied
find chapi -name '.git*' -delete
cd chapi

echo `pwd`
# Get GPO version of AMsoil from local web site
AMSOIL_VERSION=AMsoil-gpo-0.3.2
AMSOIL_FILE=${AMSOIL_VERSION}.tar.gz
#wget http://www.gpolab.bbn.com/internal/projects/chapi/${AMSOIL_FILE}
sudo cp /tmp/${AMSOIL_FILE} .
sudo tar zxf "${AMSOIL_FILE}"
sudo ln -s "${AMSOIL_VERSION}" AMsoil
cd AMsoil

# fix up the amsoil directory
for pl in chrm chapiv1rpc sarm marm csrm logging opsmon flaskrest pgch
do
    sudo ln -s ../../../chapi/plugins/$pl src/plugins/$pl
done
sudo chown apache deploy log

# tar up chapi and then the whole package
cd ../..
tar cfpz chapi.tgz chapi
cp chapi/chapi/tools/install_ch .
tar cfp chapi_installer.tar chapi.tgz install_ch
#./install_ch
sudo tar pxfz chapi.tgz -o -C /usr/share/geni-ch
GCFDIR=$(readlink /usr/share/geni-ch/gcf)
if [ ! -h /usr/share/geni-ch/gcf ]; then
  ln -s $GCFDIR /usr/share/geni-ch/gcf
fi
sudo cp /usr/share/geni-ch/chapi/chapi/tools/.bashrc /usr/share/geni-ch/

# allow www-data to write to some AMsoil directories
sudo chown apache.apache /usr/share/geni-ch/chapi/AMsoil/deploy
sudo chown apache.apache /usr/share/geni-ch/chapi/AMsoil/log

sudo chmod +w /etc/geni-ch/settings.php

# return home, we're in TMP_DIR and it's about to be deleted
cd
# Clean up the temp directory
sudo rm -rf "${TMP_DIR}"

#have to build chapi
cd "${HOME}"/chapi
autoreconf --install
./configure --prefix=/usr --sysconfdir=/etc --bindir=/usr/local/bin --sbindir=/usr/local/sbin
make
sudo make install

sudo service httpd restart

