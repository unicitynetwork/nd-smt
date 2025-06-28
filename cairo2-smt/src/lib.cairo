use core::array::ArrayTrait;
use core::poseidon::hades_permutation;

const DEFAULT_LEAF: felt252 = 0;

fn hash2(left: felt252, right: felt252) -> felt252 {
    if left == DEFAULT_LEAF {
        right
    } else if right == DEFAULT_LEAF {
        left
    } else {
        let (s0, _, _) = hades_permutation(left, right, 2);
        s0
    }
}

fn compute_forest(
    proof: @Array<Array<(u32, felt252)>>,
    initial_leaves: @Array<(u32, felt252)>,
    depth: u32,
) -> felt252 {
    let mut current_nodes = initial_leaves.clone();

    let mut level = 0;
    while level < depth {
        let mut next_level_nodes: Array<(u32, felt252)> = ArrayTrait::new();
        let proof_for_level = proof.at(level);
        let proof_for_level_len = proof_for_level.len();

        let mut i = 0;
        let mut j = 0;
        let current_nodes_len = current_nodes.len();
        while i < current_nodes_len {
            let (k, kval) = *current_nodes.at(i);
            let parent = k / 2;
            let is_left_child = (k % 2) == 0;
            let sibling_k = if is_left_child { k + 1 } else { k - 1 };
            let mut sibling_val: felt252 = DEFAULT_LEAF;

            let mut sibling_found = false;
            if is_left_child && i + 1 < current_nodes_len {
                let (next_k, next_val) = *current_nodes.at(i + 1);
                if next_k == sibling_k {
                    sibling_val = next_val;
                    i += 1; // Consume two nodes from current_nodes
                    sibling_found = true;
                }
            }
            if !sibling_found && j < proof_for_level_len {
                let (proof_k, proof_val) = *proof_for_level.at(j);
                if proof_k == sibling_k {
                    sibling_val = proof_val;
                    j += 1; // Consume the proof node
                }
            }
            let parent_val = if is_left_child {
                hash2(kval, sibling_val)
            } else {
                hash2(sibling_val, kval)
            };
            next_level_nodes.append((parent, parent_val));
            i += 1;
        };
        current_nodes = next_level_nodes;
        level += 1;
    };
    assert(current_nodes.len() == 1, 'Expected 1 node at root');
    let (_, root_val) = *current_nodes.at(0);
    root_val
}

fn verify_non_deletion(
    proof: @Array<Array<(u32, felt252)>>,
    old_root: felt252,
    new_root: felt252,
    batch: @Array<(u32, felt252)>,
    depth: u32,
) -> bool {
    // Step 1: Compute old root based on proof and empty leaves
    let mut p1: Array<(u32, felt252)> = ArrayTrait::new();
    let batch_len = batch.len();
    let mut k_idx = 0;
    while k_idx < batch_len {
        let (k, _) = *batch.at(k_idx);
        p1.append((k, DEFAULT_LEAF));
        k_idx += 1;
    };

    let r1 = compute_forest(proof, @p1, depth);
    assert(r1 == old_root, 'Root 1 mismatch');

    // Step 2: Compute new root based on siblings from proof and inserted values
    let r2 = compute_forest(proof, batch, depth);
    assert(r2 == new_root, 'Root 2 mismatch');

    true
}

#[derive(Drop, Serde)]
struct Args {
    old_root: felt252,
    new_root: felt252,
    batch: Array<(u32, felt252)>,
    proof: Array<Array<(u32, felt252)>>,
    depth: u32,
}

#[executable]
fn main(args: Args) {
    let Args { old_root, new_root, batch, proof, depth } = args;

    // Sanity checks
    assert(batch.len() > 0, 'Empty batch');
    assert(proof.len() == depth, 'Proof length mismatch');
    assert(depth > 0, 'Depth is zero');

    let result = verify_non_deletion(@proof, old_root, new_root, @batch, depth);
    assert(result, 'Verification FAILED');
}

#[cfg(test)]
mod tests {
    use super::{DEFAULT_LEAF, hash2, compute_forest, verify_non_deletion};
    use core::array::ArrayTrait;

    // Helper to create a dummy proof for testing
    fn create_dummy_proof(depth: u32) -> Array<Array<(u32, felt252)>> {
        let mut proof: Array<Array<(u32, felt252)>> = ArrayTrait::new();
        let mut i = 0;
        while i < depth {
            proof.append(ArrayTrait::new()); // Empty array for each level
            i += 1;
        }
        proof
    }

    #[test]
    fn test_hash2() {
        let h1 = hash2(1, 2);
        let expected_h1 = 2636648219362971850283425434366427370362725365790740855428580782178634926362;
        assert(h1 == expected_h1, 'hash2(1,2) failed');

        let h2 = hash2(DEFAULT_LEAF, 5);
        assert(h2 == 5, 'hash2(default,5) failed');

        let h3 = hash2(10, DEFAULT_LEAF);
        assert(h3 == 10, 'hash3(10,default) failed');

        let h4 = hash2(DEFAULT_LEAF, DEFAULT_LEAF);
        assert(h4 == DEFAULT_LEAF, 'hash4(default,default) failed');

        let h5 = hash2(100, DEFAULT_LEAF);
        let expected_h5 = 100;
        assert(h5 == expected_h5, 'hash5(100,default) failed');

        let h6 = hash2(DEFAULT_LEAF, 100);
        let expected_h6 = 100;
        assert(h6 == expected_h6, 'hash6(default,100) failed');
    }

    #[test]
    fn test_compute_forest_simple() {
        let depth = 1;
        let mut initial_leaves: Array<(u32, felt252)> = ArrayTrait::new();
        initial_leaves.append((0, 10));
        initial_leaves.append((1, 20));

        let proof = create_dummy_proof(depth);

        let root = compute_forest(@proof, @initial_leaves, depth);
        let expected_root = hash2(10, 20);
        assert(root == expected_root, 'compute_forest simple failed');
    }

    #[test]
    fn test_verify_non_deletion_simple() {
        let depth = 1;
        let mut batch: Array<(u32, felt252)> = ArrayTrait::new();
        batch.append((0, 10));
        batch.append((1, 20));

        let mut old_batch: Array<(u32, felt252)> = ArrayTrait::new();
        old_batch.append((0, DEFAULT_LEAF));
        old_batch.append((1, DEFAULT_LEAF));

        let proof = create_dummy_proof(depth);

        let old_root = compute_forest(@proof, @old_batch, depth);
        let new_root = compute_forest(@proof, @batch, depth);

        let result = verify_non_deletion(@proof, old_root, new_root, @batch, depth);
        assert(result, 'Verification failed');
    }

    #[test]
    fn test_compute_forest_single_leaf() {
        let depth = 2;
        let mut initial_leaves: Array<(u32, felt252)> = ArrayTrait::new();
        initial_leaves.append((0, 100));

        let mut proof: Array<Array<(u32, felt252)>> = ArrayTrait::new();
        let mut proof_level_0: Array<(u32, felt252)> = ArrayTrait::new();
        proof_level_0.append((1, 50));
        proof.append(proof_level_0);
        proof.append(ArrayTrait::new());

        let root = compute_forest(@proof, @initial_leaves, depth);
        let h = hash2(100, 50);
        assert(root == h, 'compute_forest 1 leaf failed');
    }
}