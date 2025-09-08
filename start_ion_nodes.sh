#!/bin/bash

NODE_COUNT=$1
BASE_DIR="./bench-ltp-group"

if [ -z "$NODE_COUNT" ]; then
    echo "Usage: ./start_ion_nodes.sh <number_of_nodes>"
    exit 1
fi

echo "########################################"
echo "Starting ION for $NODE_COUNT nodes..."
echo

# Display configuration files
CONFIGFILES="$BASE_DIR/global.ionrc"
for NODE in $(seq 1 "$NODE_COUNT"); do
    CONFIGFILES+=" $BASE_DIR/${NODE}.bench.ltp/bench.ionrc"
    CONFIGFILES+=" $BASE_DIR/${NODE}.bench.ltp/bench.bprc"
    CONFIGFILES+=" $BASE_DIR/${NODE}.bench.ltp/bench.ltprc"
    CONFIGFILES+=" $BASE_DIR/${NODE}.bench.ltp/bench.ipnrc"
done

echo "CONFIGURATION FILES:"
for FILE in $CONFIGFILES; do
    echo "$FILE:"
    cat "$FILE"
    echo "# EOF"
    echo
done

# Do not remove ion_nodes
# "$BASE_DIR/cleanup"
# sleep 1
# "$BASE_DIR/check_memory" || exit 1

export ION_NODE_LIST_DIR=$PWD

# Start nodes
for NODE in $(seq 1 "$NODE_COUNT"); do
    NODE_DIR="$BASE_DIR/${NODE}.bench.ltp"
    echo "[INFO] Starting node $NODE in $NODE_DIR"
    (cd "$NODE_DIR" && ./ionstart)
done
