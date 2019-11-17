ORIDIR=`pwd`
if [[ $0 != $BASH_SOURCE ]]; then
	cd `dirname $BASH_SOURCE` 
	cd ../bin
	SOFADIR=`pwd`
	cd $ORIDIR
fi
export PATH=$SOFADIR:$PATH
export PATH=$PATH:/usr/local/cuda/bin
export PATH=$PATH:/usr/local/intelpcm/bin
