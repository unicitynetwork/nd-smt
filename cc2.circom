pragma circom 2.0.0;

include "circomlib/poseidon.circom";
include "circomlib/bitify.circom";

template SparseMerkleTreeNonDeletion(depth) {
    signal input old_root;
    signal input new_root;
    signal input keys[depth];
    signal input values[depth];
    signal input proof[depth][depth]; // proof[i][j] is the sibling hash at level j for key i

    signal output out;

    component hash[depth+1];
    component compute_old_root;
    component compute_new_root;

    // Initialize hash components
    for (var i = 0; i < depth+1; i++) {
        hash[i] = Poseidon(2);
    }

    // Compute old root
    compute_old_root = ComputeRoot(depth, old_root, proof, keys, values, 0);
    compute_new_root = ComputeRoot(depth, new_root, proof, keys, values, 1);

    // Ensure old and new roots match the provided roots
    compute_old_root.out === old_root;
    compute_new_root.out === new_root;

    // Output 1 if both roots match, 0 otherwise
    out <== compute_old_root.out === old_root && compute_new_root.out === new_root ? 1 : 0;
}

template ComputeRoot(depth, root, proof, keys, values, is_new) {
    signal input out;

    component hash[depth+1];
    component default_leaf = Poseidon(1);

    // Initialize hash components
    for (var i = 0; i < depth+1; i++) {
        hash[i] = Poseidon(2);
    }

    // Compute the root
    signal intermediate[depth+1];
    intermediate[0] <== is_new ? values[0] : default_leaf.out;

    for (var i = 1; i < depth+1; i++) {
        if (i < depth) {
            intermediate[i] <== hash[i].out;
        } else {
            intermediate[i] <== root;
        }

        hash[i].inputs[0] <== intermediate[i-1];
        hash[i].inputs[1] <== proof[i-1];
    }

    out <== intermediate[depth];
}

component main = SparseMerkleTreeNonDeletion(256);