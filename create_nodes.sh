#!/bin/bash

# Usage: ./create_nodes.sh <number_of_nodes>
if [ -z "$1" ]; then
    echo "Usage: ./create_nodes.sh <number_of_nodes>"
    exit 1
fi

NODE_COUNT=$1
BASE_DIR="./bench-ltp-group"
BIN_NAME="mls_in_line_v11"

# Check binary exists
if [ ! -f "$BIN_NAME" ]; then
    echo "ERROR: $BIN_NAME not found in current directory."
    exit 1
fi

# Clean and recreate base directory
rm -rf "$BASE_DIR"
mkdir -p "$BASE_DIR"

# Global ionrc (hub-and-spoke: only node 1 fully connected)
GLOBAL_IONRC="$BASE_DIR/global.ionrc"
echo "m horizon  +3600" > "$GLOBAL_IONRC"
for (( i=2; i<=NODE_COUNT; i++ )); do
    echo "a range    +1 +3600       1 $i   1" >> "$GLOBAL_IONRC"
    echo "a contact  +1 +3600       1 $i   25000000" >> "$GLOBAL_IONRC"
    echo "a range    +1 +3600       $i 1   1" >> "$GLOBAL_IONRC"
    echo "a contact  +1 +3600       $i 1   25000000" >> "$GLOBAL_IONRC"
done

# Create per-node folders and config files
for NODE in $(seq 1 "$NODE_COUNT"); do
    NODE_DIR="$BASE_DIR/${NODE}.bench.ltp"
    mkdir -p "$NODE_DIR"

    # SDR size: large for node 1
    if [ "$NODE" -eq 1 ]; then
        WM_SIZE=500000000
        HEAP_WORDS=200000000
    else
        WM_SIZE=700000 #was 750000
        HEAP_WORDS=1300000 # was 1500000
    fi

    cat <<EOL > "$NODE_DIR/bench.ionconfig"
wmKey 66${NODE}36
sdrName ion${NODE}
wmSize $WM_SIZE
configFlags 1
heapWords $HEAP_WORDS
EOL

    # bench.ionrc
    cat <<EOL > "$NODE_DIR/bench.ionrc"
1 ${NODE} bench.ionconfig
s
m horizon +3600
EOL

    echo "1" > "$NODE_DIR/bench.ionsecrc"

    # bench.ipnrc
    IPNRC_FILE="$NODE_DIR/bench.ipnrc"
    > "$IPNRC_FILE"
    if [ "$NODE" -eq 1 ]; then
        for (( OTHER=2; OTHER<=NODE_COUNT; OTHER++ )); do
            echo "a plan $OTHER ltp/$OTHER" >> "$IPNRC_FILE"
        done
    else
        echo "a plan 1 ltp/1" >> "$IPNRC_FILE"
    fi

    # bench.ltprc
    LTP_PORT=$((2110 + NODE))
    LTPRC_FILE="$NODE_DIR/bench.ltprc"
    echo "1 100000" > "$LTPRC_FILE"
    if [ "$NODE" -eq 1 ]; then
        for (( OTHER=2; OTHER<=NODE_COUNT; OTHER++ )); do
            echo "a span $OTHER 100 100 64000 1000000 1 'udplso localhost:$((2110 + OTHER))'" >> "$LTPRC_FILE"
        done
    else
        echo "a span 1 100 100 64000 1000000 1 'udplso localhost:2111'" >> "$LTPRC_FILE"
    fi
    echo "s 'udplsi localhost:$LTP_PORT'" >> "$LTPRC_FILE"

    # bench.bprc
    BPRC_FILE="$NODE_DIR/bench.bprc"
    cat <<EOL > "$BPRC_FILE"
1
a scheme ipn 'ipnfw' 'ipnadminep'
EOL

    if [ "$NODE" -eq 1 ]; then
        echo "a endpoint ipn:1.1 q" >> "$BPRC_FILE"
        for (( OTHER=2; OTHER<=NODE_COUNT; OTHER++ )); do
            echo "a endpoint ipn:1.$OTHER q" >> "$BPRC_FILE"
        done
    else
        echo "a endpoint ipn:$NODE.1 q" >> "$BPRC_FILE"
    fi

    cat <<EOL >> "$BPRC_FILE"
a protocol ltp 1400 100
a induct ltp $NODE ltpcli
EOL

    if [ "$NODE" -eq 1 ]; then
        for (( OTHER=2; OTHER<=NODE_COUNT; OTHER++ )); do
            echo "a outduct ltp $OTHER ltpclo" >> "$BPRC_FILE"
        done
    else
        echo "a outduct ltp 1 ltpclo" >> "$BPRC_FILE"
    fi

    echo "r 'ipnadmin bench.ipnrc'" >> "$BPRC_FILE"
    echo "s" >> "$BPRC_FILE"

    # ionstart
    cat <<EOL > "$NODE_DIR/ionstart"
#!/bin/bash
ionadmin bench.ionrc
sleep 0.25
ionadmin ../global.ionrc
sleep 0.25
ionsecadmin bench.ionsecrc
sleep 0.25
ltpadmin bench.ltprc
sleep 0.25
bpadmin bench.bprc
EOL
    chmod +x "$NODE_DIR/ionstart"

    # ionstop
    cat <<EOL > "$NODE_DIR/ionstop"
#!/bin/bash
bpadmin .
sleep 0.25
ltpadmin .
sleep 0.25
ionadmin .
EOL
    chmod +x "$NODE_DIR/ionstop"

    # copy binary
    cp "$BIN_NAME" "$NODE_DIR/"
done

echo "All nodes created successfully in $BASE_DIR"
