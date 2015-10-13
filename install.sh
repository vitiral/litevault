SCRIPT=$(readlink -f "$0")
SCRIPTPATH=$(dirname "$SCRIPT")
INSTALL_PATH=/usr/bin/litevault

cp $SCRIPTPATH/litevault.py $INSTALL_PATH
chmod a+x $INSTALL_PATH
