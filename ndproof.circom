pragma circom 2.0.0;

// include "node_modules/circomlib/circuits/sha256/sha256.circom";
include "node_modules/circomlib/circuits/poseidon.circom";
include "node_modules/circomlib/circuits/bitify.circom";
include "node_modules/circomlib/circuits/multiplexer.circom";

template PickOne(N) {
    signal input in[N];
    signal input sel;
    signal output out;

    component mux = Multiplexer(1, N);
    for (var i = 0; i < N; i++) {
        mux.inp[i][0] <== in[i];
    }
    mux.sel <== sel;
    out <== mux.out[0];
}

template Hash2() {
    signal input L;
    signal input R;
    signal output out;

    component h = Poseidon(2);
    h.inputs[0] <== L;
    h.inputs[1] <== R;

    out <== h.out;
}

template Cell(N) {
    signal input controlL;
    signal input controlR;
    signal input in[N];
    signal input proof[N];
    signal output out;

    component muxL = PickOne(2*N);
    component muxR = PickOne(2*N);
    component hasher = Hash2();

    for (var i = 0; i < N; i++) {
        muxL.in[i] <== in[i];
        muxR.in[i] <== in[i];
    }

    for (var i = 0; i < N; i++) {
        muxL.in[N+i] <== proof[i];
        muxR.in[N+i] <== proof[i];
    }
    muxL.sel <== controlL;
    muxR.sel <== controlR;
    hasher.L <== muxL.out;
    hasher.R <== muxR.out;
    out <== hasher.out;
}

template ForestHasher(DEPTH, WIDTH) {
    signal input batch[WIDTH];
    signal input proof[WIDTH];
    signal input controlL[DEPTH][WIDTH];
    signal input controlR[DEPTH][WIDTH];
    signal output root;

    component cell[DEPTH][WIDTH];
    // Internal signals
    signal intermediateRoots[DEPTH][WIDTH];

    for (var d = 0; d < DEPTH; d++) {
        // Calculate the number of cells in this layer, it is a binary tree and shrinks towards root
        var numCells = 1 << (DEPTH - 1 - d); // 2^(DEPTH-1-d)
        if (numCells > WIDTH) {
            numCells = WIDTH;
        }
        for (var i = 0; i < numCells; i++) {
            cell[d][i] = Cell(WIDTH);
            cell[d][i].controlL <== controlL[d][i];
            cell[d][i].controlR <== controlR[d][i];
            if (d == 0) {
                cell[d][i].in <== batch;   // leaves connect to input batch
            } else {
                // intermediate wires with no cells to connect are connected to 0
                var prevLayerCells = 1 << (DEPTH - d);
                if (prevLayerCells > WIDTH) {
                    prevLayerCells = WIDTH;
                }
                for (var j = 0; j < prevLayerCells; j++) {
                    cell[d][i].in[j] <== intermediateRoots[d-1][j];
                }
                for (var j = prevLayerCells; j < WIDTH; j++) {
                    cell[d][i].in[j] <== 0;
                }
            }
            cell[d][i].proof <== proof;
            intermediateRoots[d][i] <== cell[d][i].out;
        }
    }

    root <== intermediateRoots[DEPTH-1][0];
}

template NdVerifier(DEPTH, WIDTH) {
    signal input batch[WIDTH];
    signal input proof[WIDTH];
    signal input root1;
    signal input root2;
    signal input controlL[DEPTH][WIDTH];
    signal input controlR[DEPTH][WIDTH];
    signal result1;
    signal result2;

    component fh1 = ForestHasher(DEPTH, WIDTH);
    for (var i = 0; i < WIDTH; i++) {
        fh1.batch[i] <== 0;
    }
    fh1.proof <== proof; // assignment works for whole array?
    for (var i = 0; i < DEPTH; i++) {
        for (var j = 0; j < WIDTH; j++) {
            fh1.controlL[i][j] <== controlL[i][j];
            fh1.controlR[i][j] <== controlR[i][j];
        }
    }
    result1 <== fh1.root;
    result1 === root1;

    component fh2 = ForestHasher(DEPTH, WIDTH);
    fh2.batch <== batch;
    fh2.proof <== proof;
    for (var i = 0; i < DEPTH; i++) {
        for (var j = 0; j < WIDTH; j++) {
            fh2.controlL[i][j] <== controlL[i][j];
            fh2.controlR[i][j] <== controlR[i][j];
        }
    }
    result2 <== fh2.root;
    result2 === root2;
}

component main {public [batch, root1, root2]} = NdVerifier(16, 10);
