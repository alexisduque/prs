#!/bin/bash
#set -x 

# variables 
TERMINAL=xterm
# TERMOPTION
BASE=2000
# STARTI=0

VALGRIND="valgrind --leak-check=full --show-reachable=yes --track-origins=yes"

#VALGRIND=""
VERBOSE=6

if [ "$BASE" == "" ] ; then
    export BASE=2000
fi

if [ "$STARTI" == "" ] ; then
    export STARTI=0
fi

if [ "$TERMINAL" == "" ] ; then
    export TERMINAL=xterm
fi


usage()
{
cat <<EOF
start_server 
  c [n] : start a client [to server n]
  d [n] : start [n] detached server
          [n] : if [n] > 1 then connect server(i) with server(i-1) 
  x [n] : start [n] server in a xterm
          [n] : if [n] > 1 then connect server(i) with server(i-1) 
  f [n] : find pid of server [n]
  g [n] : start gdb and connect to it to server [n]
  k : kill all servers


BASE=x start_server [] 
  default BASE=0
EOF
}

server_name()
{
    echo alex_node_$1
}

base()
{
    echo `expr $BASE + $1`
}

port_ui()
{
    echo `base $1`1
}

port_tcp()
{
    echo `base $1`2
}

port_udp()
{
    echo `base $1`3
}

start_line()
{
    NUM=$1
    DIR=$2
    DST=$3
    OTHER=$4

    echo ${VALGRIND} ${DIR}/p2p_node       \
	--dir=${DST}                       \
	--listening-ip=127.0.0.1       \
	--server-name=`server_name ${NUM}` \
	--ui-tcp-port=`port_ui ${NUM}`     \
	--p2p-tcp-port=`port_tcp ${NUM}`   \
	--p2p-udp-port=`port_udp ${NUM}`   \
	--verbose=${VERBOSE}               \
	${OTHER}
}

find_server_pid()
{
    SERVER_NAME=`server_name $1`
    echo `ps aux | grep ${SERVER_NAME} | egrep -v 'xterm|bash|grep' | cut -d ' ' -f 2`
}


start_serv()
{
    MODE=$1
    NUM=$2
    DIR=$3
    OTHER=$4
    TMPDIR=/home/alex/Documents/PRS
    DST=${TMPDIR}/alex_dir_${NUM}
    mkdir -p ${DST}
    touch ${DST}/p2p_${NUM}
    echo "file from node ${NUM}" > ${DST}/p2p_${NUM}
    echo -n "starting node ${NUM} : "
    case "${MODE}" in
	"x" )
	    CMDLINE="`start_line ${NUM} ${DIR} ${DST} ${OTHER}`"
	    # `start_line ${NUM} ${DIR} ${DST} ${OTHER}`
	    echo ${CMDLINE}
	    #${CMDLINE}
	    ${TERMINAL} -geometry 99x24 -title Server_Alex_T${NUM} -e "${CMDLINE} ; read " &
	;;
	"d" )
	    `start_line ${NUM} ${DIR} ${DST} ${OTHER}` &
	;;
	* )
	    usage
	    exit 1
	;;
    esac
    sleep 1
    echo pid=`find_server_pid ${NUM}`
}



if [ $# -lt 1  ] ; then
    usage
    exit 1
else
    case "$1" in
	"c" )
	    if [ $# -gt 1 ] ; then 
		NUM=$2
		${TERMINAL} -title client_T${NUM} -e telnet localhost `port_ui $NUM` &
	    else
		${TERMINAL} -e telnet &
	    fi 
	    ;;
	"d" | "x" )
	    DIR=`dirname $0`
	    start_serv $1 $STARTI ${DIR}
	    I=`expr ${STARTI} + 1`
	    if [ $# -gt 1 ] ; then
		while [ $I -lt $2 ] ; do
		    IM=`expr $I - 1`
		    start_serv $1 $I ${DIR} --connect=127.0.0.1::`port_tcp $IM`:`port_udp $IM`
		    I=`expr $I + 1`
		done
	    fi
	    ;;
	"k" )
	    killall -9 p2p_node
	    ;;
	"f" ) 
	    echo server $2 : pid=`find_server_pid $2`
	    ;;
	"g" )
	    gdb `dirname $0`/p2p_node `find_server_pid $2`
	    ;;
	"D" )
	    ddd `dirname $0`/p2p_node `find_server_pid $2`
	    ;;
	* ) 
	    usage
	    ;;
    esac
fi
    
