%builtins output range_check poseidon

from starkware.cairo.common.serialize import serialize_word
from starkware.cairo.common.cairo_builtins import PoseidonBuiltin
from starkware.cairo.common.builtin_poseidon.poseidon import poseidon_hash
from starkware.cairo.common.math import assert_nn, unsigned_div_rem
from starkware.cairo.common.alloc import alloc

// Constants
const DEFAULT = 0;

// Struct for proof nodes: each node has a path length, path, and value
struct ProofNode {
    path_len: felt,  // Length of the path bitstring (0 to depth)
    path: felt,      // Path as a felt (bits packed, MSB is root level)
    value: felt,     // Value of the node
}

// Struct for leaf nodes: used for addition batch keys and values
struct LeafNode {
    path: felt,   // Path as a felt (depth bits)
    value: felt,  // Value at that leaf
}

// Search for a node in the proof array with given path_len and path
func find_in_proof{range_check_ptr}(
    proof_array: ProofNode*,
    index: felt,
    max_index: felt,
    target_path_len: felt,
    target_path: felt
) -> (found: felt, value: felt) {
    if (index == max_index) {
        return (0, 0);  // Not found
    }
    let node = proof_array[index];
    if (node.path_len == target_path_len) {
        if (node.path == target_path) {
            return (1, node.value);
        }
    }
    return find_in_proof(proof_array, index + 1, max_index, target_path_len, target_path);
}
// same using hint and no recursion
func find_in_proof2{range_check_ptr}(
    proof_array: ProofNode*,
    index: felt,
    max_index: felt,
    target_path_len: felt,
    target_path: felt
) -> (found: felt, value: felt) {
    alloc_locals;
    local found:felt;
    local index:felt;
    %{
        found = 0
        index = 0
        for i in range(ids.max_index):
            base = ids.proof_array.address_ + ids.ProofNode.SIZE * i
            if memory[base + ids.ProofNode.path_len] == ids.target_path_len and memory[base + ids.ProofNode.path] == ids.target_path:
                found = 1
                index = i
                break
        ids.found = found
        ids.index = index
    %}
    if (found == 0) {
        return ((found=0, value=0));
    } else {
        assert proof_array[index].path_len = target_path_len;
        assert proof_array[index].path = target_path;
        return ((found=found, value=proof_array[index].value));
    }
}


// Search for a leaf in the extra array with given path
func find_in_extra{range_check_ptr}(
    extra_array: LeafNode*,
    index: felt,
    max_index: felt,
    target_path: felt
) -> (found: felt, value: felt) {
    if (index == max_index) {
        return (0, 0);  // Not found
    }
    let node = extra_array[index];
    if (node.path == target_path) {
        return (1, node.value);
    }
    return find_in_extra(extra_array, index + 1, max_index, target_path);
}

// same using hint and no recursion
func find_in_extra2{range_check_ptr}(
    extra_array: LeafNode*,
    index: felt,
    max_index: felt,
    target_path: felt
) -> (found: felt, value: felt) {
    alloc_locals;
    local found:felt;
    local index:felt;
    %{
        found = 0
        index = 0
        for i in range(ids.max_index):
            base = ids.extra_array.address_ + ids.LeafNode.SIZE * i
            if memory[base + ids.LeafNode.path] == ids.target_path:
                index = i
                found = 1
                break
        ids.found = found
        ids.index = index
    %}
    if (found == 0) {
        return ((found=0, value=0));
    } else {
        assert extra_array[index].path = target_path;
        return ((found=found, value=extra_array[index].value));
    }
}

// Hash two elements with special handling for 'default' values
func hash{poseidon_ptr: PoseidonBuiltin*}(l: felt, r: felt) -> (out: felt) {
    if (l == DEFAULT) {
        if (r == DEFAULT) {
            return (out = DEFAULT);
        }
    }
    let (res) = poseidon_hash(l, r);
    return (out = res);
}

func fill_values(
    extra: LeafNode*,
    in: LeafNode*,
    value: felt,
    index: felt,
    len: felt
) {
    if (index == len) {
        return ();
    }
    assert extra[index] = LeafNode(path=in[index].path, value=value);
    fill_values(extra, in, value, index + 1, len);
    return ();
}

// Fill the extra array with batch values for the batch keys
func fill_extra_with_values(
    extra: LeafNode*,
    keys: felt*,
    values: felt*,
    index: felt,
    len: felt
) {
    if (index == len) {
        return ();
    }
    assert extra[index] = LeafNode(path=keys[index], value=values[index]);
    fill_extra_with_values(extra, keys, values, index + 1, len);
    return ();
}

func process_level_keys{range_check_ptr, poseidon_ptr: PoseidonBuiltin*, output_ptr: felt*}(
    forest: ProofNode*,
    forest_len: felt,
    extra: LeafNode*,
    extra_len: felt,
    next_extra: LeafNode*,
    next_extra_len: felt,
    layer_w: felt*,
    depth: felt,
    keys_processed: felt, // Number of keys processed so far at this layer
    last_parent: felt     // To avoid redundant computation of same parent
) -> (result: felt){

    alloc_locals;
    // %{print(f">process_level_keys(forest_len:{ids.forest_len} extra_len:{ids.extra_len} depth: {ids.depth}  keys_processed:{ids.keys_processed} last_parent:{ids.last_parent}  )")%}
    if (keys_processed == extra_len) {
        // All keys have been processed at the current level
        assert_nn(depth-1);

        // extra <- next_extra
        return compute_forest_recursive(forest, forest_len, next_extra, next_extra_len, layer_w, depth-1);
    }

    local current_key = extra[keys_processed].path;
    local current_val = extra[keys_processed].value;

    let (local parent, last_bit) = unsigned_div_rem(current_key, 2);
    let frozen_range_check_ptr = range_check_ptr;

    // for example when input contains two sibling leaves there is no point in calculating the parent twice
    // perhaps better alternative is to jump over next sorted input if sibling is the next
    if (parent == last_parent){
        return process_level_keys(forest, forest_len, extra, extra_len, next_extra, next_extra_len, layer_w, depth, keys_processed+1, last_parent);
    }

    let sibling = parent * 2 + (1 - last_bit);

    let (found, sibling_val) = find_in_extra2(extra, 0, extra_len, sibling);
    if (found == 0) {
        let (found, sibling_val_temp) = find_in_proof2(forest, 0, forest_len, depth, sibling);
        if (found == 0) {
            tempvar sibling_val = DEFAULT;
        } else {
            tempvar sibling_val = sibling_val_temp;
        }
    } else {
        tempvar sibling_val = sibling_val;
    }

    // Hash the pair
    if (last_bit == 0){
        let (pv) = hash(current_val, sibling_val);
    } else {
        let (pv) = hash(sibling_val, current_val);
    }

    // There is only 1 parent (the root) for layer 1.
    if (depth == 1) {
        tempvar range_check_ptr = frozen_range_check_ptr;
        return (result=pv);
    }

    // a dict of intermediate nodes for the next layer
    assert next_extra[next_extra_len] = LeafNode(path=parent, value=pv);
    local next_extra_len = next_extra_len + 1;

    tempvar range_check_ptr = frozen_range_check_ptr;
    return process_level_keys(forest, forest_len, extra, extra_len, next_extra, next_extra_len, layer_w, depth, keys_processed+1, parent);
}

// Function to compute the forest recursively
func compute_forest_recursive{range_check_ptr, poseidon_ptr: PoseidonBuiltin*, output_ptr: felt*}(
    forest: ProofNode*,
    forest_len: felt,
    extra: LeafNode*,
    extra_len: felt,
    layer_w: felt*,
    depth: felt     // Current level, decreased during recursion
) -> (result: felt) {

    alloc_locals;
    // %{print(f">compute_forest_recursive(forest_len:{ids.forest_len} extra_len:{ids.extra_len} depth: {ids.depth})")%}

    assert_nn(depth);

    let (next_extra: LeafNode*) = alloc();
    let next_extra_len:felt = 0;

                    // last 2 parameters: # of keys processed at the level, parent.
   return process_level_keys(forest, forest_len, extra, extra_len, next_extra, next_extra_len, layer_w, depth, 0, -1);
}

func main{output_ptr: felt*, range_check_ptr, poseidon_ptr: PoseidonBuiltin*}() -> (){
    alloc_locals;

    local old_root: felt;
    local new_root: felt;
    local depth: felt;

    let (input: LeafNode*) = alloc();
    local input_len:felt;

    let (proof: ProofNode*) = alloc();
    local proof_len:felt;

    let layer_w: felt* = alloc();  // how many proof siblings per layer, unused currently

        // witness_data = {
        //     "old_root": old_root,
        //     "new_root": new_root,
        //     "keys": keys,
        //     "values": values,
        //     "proof": proof,   // dict
        //     "depth": self.depth
        // }
    %{
        ids.old_root = program_input['old_root']
        ids.new_root = program_input['new_root']
        ids.depth = program_input['depth']

        ids.input_len = len(program_input['keys'])
        for i, (k, v) in enumerate(sorted(zip(program_input['keys'], program_input['values']))):
            base = ids.input.address_ + ids.LeafNode.SIZE * i
            memory[base + ids.LeafNode.path] = k
            memory[base + ids.LeafNode.value] = v

        layer_w = [0] * (ids.depth + 1)
        proof_list = sorted(program_input['proof'].items(), key=lambda k: (-len(k[0]), k[0]))
        ids.proof_len = len(proof_list)
        for i, (k, v) in enumerate(proof_list):
            base = ids.proof.address_ + ids.ProofNode.SIZE * i
            memory[base + ids.ProofNode.path_len] = len(k)
            memory[base + ids.ProofNode.path] = int(k, 2)  # expects non-empty string with binary number
            memory[base + ids.ProofNode.value] = v
            layer_w[len(k)] += 1

        for i, k in enumerate(layer_w):
            memory[ids.layer_w + i] = k
    %}

    // Allocate and fill 'blank' with default values for batch keys
    let (blanks: LeafNode*) = alloc();
    fill_values(blanks, input, DEFAULT, 0, input_len);

    // Step 1: Compute old root
    let (r1) = compute_forest_recursive(proof, proof_len, blanks, input_len, layer_w, depth);
    assert r1 = old_root;

    // Step 2: Compute new root, where the blanks are replaced with values in the insertion batch
    let (r2) = compute_forest_recursive(proof, proof_len, input, input_len, layer_w, depth);
    assert r2 = new_root;

    return();
}