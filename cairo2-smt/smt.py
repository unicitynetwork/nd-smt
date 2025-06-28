from poseidon_py.poseidon_hash import poseidon_perm
import json
import sys

# Cairo's hardcoded Poseidon parameters:
# https://github.com/starkware-industries/poseidon/blob/main/poseidon3.txt
# and P = 2**251 + 17 * 2**192 + 1

default = 0  # default 'empty' leaf

def hash2(left, right):
    # The following assumes that leaf's address/key/hash is bound to leaf's value
    if left == default:
        return right
    elif right == default:
        return left
    else:
        return poseidon_perm(left, right, 2)[0]

class SparseMerkleTree:
    def __init__(self, depth=256):
        self.depth = depth
        # Node dictionary stores (level, key_integer) -> value
        self.nodes = {}
        self.default = [default] * (depth + 1)
        # Precompute default hashes for each level
        for i in range(1, depth + 1):
            self.default[i] = hash2(self.default[i-1], self.default[i-1])

    def get_root(self):
        return self.get_node(self.depth, 0)

    def get_node(self, level, key):
        """Gets a node's value. key is an integer."""
        return self.nodes.get((level, key), self.default[level])

    def update_node(self, level, node):
        key, value = node
        self.nodes[(level, key)] = value

    def batch_insert(self, nodes):
        """
        Inserts a batch of nodes into the tree and generates a proof of non-deletion.
        The proof consists of sibling nodes required to verify the state transition.
        """

        # Filter out keys that already exist in the tree to avoid failing the entire batch
        new_nodes = []
        for key, value in nodes:
            if (0, key) in self.nodes:
                print(f"The leaf '{key}' is already set, skipping.", file=sys.stderr)
            else:
                new_nodes.append((key, value))

        if not new_nodes:
            return [[] for _ in range(self.depth)]  # No changes, empty proof

        # Sort the new key-value pairs by key
        new_nodes.sort()
        new_keys = [k for k, _ in new_nodes]

        # Insert all new leaves at level 0
        for node in new_nodes:
            self.update_node(0, node)

        proof = [[] for _ in range(self.depth)]  # proof[level] = [(key, value), ...]

        # 'affected_keys_at_level' are the keys of nodes at a given level
        # that are on the path of the inserted leaves.
        affected_keys_at_level = set(new_keys)

        for level in range(self.depth):  # Iterate from leaves (level 0) up to root
            parent_keys = {k >> 1 for k in affected_keys_at_level}

            # For each parent, find the required siblings at the current level
            for p_key in parent_keys:
                left_child_key = p_key << 1
                right_child_key = left_child_key | 1

                is_left_affected = left_child_key in affected_keys_at_level
                is_right_affected = right_child_key in affected_keys_at_level

                # If one child is affected and the other is not, the unaffected one is a
                # sibling needed for the proof.
                if is_left_affected and not is_right_affected:
                    sibling_val = self.get_node(level, right_child_key)
                    if sibling_val != self.default[level]:
                        proof[level].append((right_child_key, sibling_val))

                if is_right_affected and not is_left_affected:
                    sibling_val = self.get_node(level, left_child_key)
                    if sibling_val != self.default[level]:
                        proof[level].append((left_child_key, sibling_val))

            # Calculate and update the parent nodes in the tree
            for p_key in parent_keys:
                left_child_key = p_key << 1
                right_child_key = left_child_key | 1

                left_val = self.get_node(level, left_child_key)
                right_val = self.get_node(level, right_child_key)

                p_val = hash2(left_val, right_val)
                self.update_node(level + 1, (p_key, p_val))

            # The affected keys for the next level are the parent keys we just processed
            affected_keys_at_level = parent_keys

        # Sort the proof lists for deterministic output
        for level_proof in proof:
            level_proof.sort()

        return proof

def verify_non_deletion(proof, old_root, new_root, batch, depth):
    # computing from leaves towards root. This is also important for security: we show that based on leaves
    # we reach a specific root, and intermediate hashes from the proof must not override the chains.
    def compute_forest(nodes):
        for level in range(depth):
            next_nodes = []
            lproof = proof[level]
            i, j = 0, 0
            while i < len(nodes):
                k, kval = nodes[i]
                parent = k // 2             # unsigned_div_rem()
                last_bit = k % 2
                sibling = parent * 2 + (1 - last_bit) # zk friendlier than bitwise
                if last_bit == 0 and i != len(nodes)-1 and nodes[i+1][0] == sibling:
                    i = i + 1
                    siblingval = nodes[i][1]
                elif j < len(lproof) and lproof[j][0] == sibling:
                    siblingval = lproof[j][1]
                    j = j + 1
                else:
                    siblingval = default

                pv = hash2(kval, siblingval) if last_bit == 0 else hash2(siblingval, kval)
                next_nodes.append((parent, pv))
                i = i + 1
            nodes = next_nodes
        assert len(nodes) == 1  # 1 node at the root level
        return nodes[0][1]

    if not batch:
        return old_root == new_root

    # step 1. compute old root based on proof and 'empty' leaves in place of new batch
    p1 = [(key, default) for key, _ in batch]  # empty leaves
    r1 = compute_forest(p1)
    if r1 != old_root:
        print(f"Non-deletion proof root 1 mismatch: r:{r1}, oldr:{old_root}", file=sys.stderr)
        return False

    # step 2. compute new root based on proof and leaves from the batch
    r2 = compute_forest(batch)
    if r2 != new_root:
        print(f"Non-deletion proof root 2 mismatch: r:{r2}, newr:{new_root}", file=sys.stderr)
        return False

    # it is possible to compute the root based on
    #   1. empty leaves and the proof - giving the root before batch insertion,
    #   2. leaves in the batch and the proof - giving the root after batch insertion
    #  with the proof content being exactly the same.
    #  Proof is the roots of hash subtrees which did not change during the insertion
    #  thus only the leaves given in the batch did change, everything else is the same
    # and because we explicitly marked the leaves to be added as blank (default) before
    #  the first check, we know that these leaves were blank before inserting the batch,
    #  thus nothing was overwritten
    return True


def main():
    depth = 32

    def to_int(aa):
        if isinstance(aa, (list, tuple)):
            return [to_int(a) for a in aa]
        elif isinstance(aa, bytes):
            return int.from_bytes(aa, byteorder='big')
        else:
            # Fallback for whatever with __str__
            return int.from_bytes(str(aa).encode(), byteorder='big')

    smt = SparseMerkleTree(depth)

    keys = to_int([b'\x01', b'\x02', b'\x03']) # test adjacent key handling
    values = to_int([b'value1', b'value2', b'value3'])
    batch = sorted(zip(keys, values))

    old_root = smt.get_root()
    proof = smt.batch_insert(batch)
    new_root = smt.get_root()
    assert verify_non_deletion(proof, old_root, new_root, batch, depth)

    # --- pre-filling the tree ---
    batch = []
    for i in range(1000):
        rk = hash("a" + str(i)) % (2**depth)
        rv = to_int("Val " + str(rk))
        if (rk, rv) in batch: continue
        batch.append((rk, rv))

    print(f"Pre-filling the SMT with {len(batch)} items.", file=sys.stderr)

    old_root = new_root
    proof = smt.batch_insert(batch)
    new_root = smt.get_root()
    assert verify_non_deletion(proof, old_root, new_root, sorted(batch), depth)

    # --- batch for proving ---
    batch = []
    for i in range(1000):
        rk = hash("b" + str(i)) % (2**depth)
        rv = to_int("Val " + str(rk))
        if (rk, rv) in batch: continue
        batch.append((rk, rv))

    batch = sorted(batch)
    old_root = new_root
    print(f"Preparing witness for a batch of {len(batch)} items.", file=sys.stderr)
    proof = smt.batch_insert(batch)
    print("Insertion and proof generation done.", file=sys.stderr)
    new_root = smt.get_root()
    assert verify_non_deletion(proof, old_root, new_root, batch, depth)

    witness_data = {
        "old_root": old_root,
        "new_root": new_root,
        "batch": batch,
        "proof": proof,
        "depth": depth
    }
    print(json.dumps(witness_data, indent=4))


if __name__ == "__main__":
    main()
