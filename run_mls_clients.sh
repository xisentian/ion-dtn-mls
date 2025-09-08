#!/bin/bash

NODE_COUNT=$1
GROUP_SIZE=$2
BASE_DIR="./bench-ltp-group"
BIN_NAME="mls_in_line_v11"

if [ -z "$NODE_COUNT" ] || [ -z "$GROUP_SIZE" ]; then
    echo "Usage: ./run_mls_clients.sh <number_of_nodes> <initial_group_size>"
    exit 1
fi

if ! command -v gnome-terminal &> /dev/null; then
    echo "Error: gnome-terminal not found. This script requires GNOME Terminal."
    exit 1
fi

# Absolute path to top-level ION_NODE_LIST_DIR
ROOT_DIR=$(pwd)
# ROOT_DIR="/home/ubuntu/Desktop/ion/ION-DTN/demos/"

# Terminal window settings
WIDTH=70
HEIGHT=30
DX=800  # horizontal spacing between terminals
DY=500  # vertical spacing (not used since just 2 windows)
X_OFFSET=0
Y_OFFSET=0

i=0
for NODE in $(seq 1 "$NODE_COUNT"); do
    NODE_DIR="${BASE_DIR}/${NODE}.bench.ltp"
    ABS_NODE_DIR=$(realpath "$NODE_DIR")
    SOURCE_EID="ipn:${NODE}.1"

    if [ "$NODE" -eq 1 ]; then
        CMD="./$BIN_NAME $GROUP_SIZE $SOURCE_EID"
    else
        DEST_EID="ipn:1.1"
        CMD="./$BIN_NAME $GROUP_SIZE $SOURCE_EID $DEST_EID"
    fi

    echo "[INFO] Starting $CMD in $NODE_DIR"
    
    sleep 1

    if [ "$NODE" -eq 1 ] || [ "$NODE" -eq 2 ]; then
        X=$(( (NODE - 1) * DX + X_OFFSET ))  # place node1 at X=0, node2 at X=800
        Y=$Y_OFFSET
	gnome-terminal --geometry=${WIDTH}x${HEIGHT}+${X}+${Y} \
	  -- bash -c "cd '$ABS_NODE_DIR'; export ION_NODE_LIST_DIR='$ROOT_DIR'; $CMD |& tee -a 'mls_output_node${NODE}.log'; exec bash"

    else
        (
            cd "$ABS_NODE_DIR"
            export ION_NODE_LIST_DIR="$ROOT_DIR"
            $CMD > "mls_output_node${NODE}.log" 2>&1 &
        )
    fi

    i=$((i + 1))
done
