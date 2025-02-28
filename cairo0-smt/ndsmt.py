# import hashlib
from starkware.cairo.common.poseidon_hash import poseidon_hash
import pprint
import sys
import random
import json

default = 0  # default 'empty' leaf

def hash(left, right):
    if left == default and right == default:
        return default
    else:
        return poseidon_hash(left, right)


class SparseMerkleTree:
    def __init__(self, depth=256):
        self.depth = depth
        self.nodes = {}
        self.default = [default] * (depth + 1)
        # Precompute default hashes for each level
        for i in range(1, depth + 1):
            self.default[i] = hash(self.default[i-1], self.default[i-1])

    def get_root(self):
        return self.get_node(self.depth, '')

    def get_node(self, level, path):
        return self.nodes.get((level, path), self.default[level])

    def update_node(self, level, path, value):
        if level == 0 and not (self.nodes.get((0, path)) is None):
            print(f"The leaf '{path}' is already set", file=sys.stderr)
            return
        self.nodes[(level, path)] = value

    def insert(self, key, value):
        path = self.key_to_bits(key)
        current = value
        self.update_node(0, path, current)

        for level in range(1, self.depth + 1):
            parent_path = path[:-level] if level < self.depth else ''
            bit = path[-level] if level <= len(path) else '0'

            if bit == '0':
                left = current
                right = self.get_node(level-1, parent_path + '1')
            else:
                left = self.get_node(level-1, parent_path + '0')
                right = current

            current = hash(left, right)
            self.update_node(level, parent_path, current)
        return current

    def generate_inclusion_proof(self, key):
        # returns inclusion proof for existing key
        # returns non-inclusion proof for unknown key
        #     that is, the default leaf
        path = self.key_to_bits(key)
        proof = []
        current_path = path

        for level in range(self.depth):
            parent_path = current_path[:-1] if level < self.depth-1 else ''
            last_bit = current_path[-1] if current_path else '0'

            if last_bit == '0':
                sibling_path = parent_path + '1'
            else:
                sibling_path = parent_path + '0'

            sibling_node = self.get_node(level, sibling_path)
            proof.append(sibling_node)
            current_path = parent_path

        return proof

    def missing_keys(self, keys):
        # take all chains of siblings
        # make unique
        # remove keys
        # remove prefixes
        def sibling_paths(path):
            paths = []
            current_path = path

            for level in range(self.depth):
                parent_path = current_path[:-1] if level < self.depth-1 else ''
                last_bit = current_path[-1] if current_path else '0'

                if last_bit == '0':
                    sibling_path = parent_path + '1'
                else:
                    sibling_path = parent_path + '0'

                paths += [sibling_path]
                current_path = parent_path

            return paths

        def prefix_free(bitstrings):
            result = set()
            for s in sorted(bitstrings, key=lambda x: (len(x), x)):
                if not any(other.startswith(s) and other != s for other in bitstrings):
                    result.add(s)

            return result

        siblings = []
        paths = []
        for key in keys:
            path = self.key_to_bits(key)
            siblings += sibling_paths(path)
            paths += [path]

        siblings = set(siblings) - set(paths)
        siblings = prefix_free(siblings)
        return siblings

    def verify_inclusion_proof(self, key, value, proof):
        path = self.key_to_bits(key)
        current = value

        for level in range(self.depth):
            sibling = proof[level]
            bit = path[-level-1] if level < len(path) else '0'

            if bit == '0':
                current = hash(current, sibling)
            else:
                current = hash(sibling, current)

        return current

    def verify_non_inclusion_proof(self, key, proof):
        path = self.key_to_bits(key)
        current = self.default[0]  # Start with the default leaf node

        for level in range(self.depth):
            sibling = proof[level]
            bit = path[-level-1] if level < len(path) else '0'

            if bit == '0':
                current = hash(current, sibling)
            else:
                current = hash(sibling, current)

        return current

    def key_to_bits(self, key):
        # Convert key to a string of 'depth' bits
        #return format(int.from_bytes(key, 'big'), '0{}b'.format(self.depth))
        return format(key, '0{}b'.format(self.depth))

    def batch_insert(self, keys, values):
        proof = {}
        # proof of consistency: collect all siblings necessary to compute root
        # based on new batch of keys
        # 'default' leaves are NOT included
        for k in self.missing_keys(keys):
            level = self.depth - len(k)
            if level >= self.depth or level < 0:
                raise ValueError(f"Panic, level {level} out of range")
            v = self.get_node(level, k)
            if v != default:
                proof[k] = v

        # Perform all insertions
        for key, value in zip(keys, values):
            self.insert(key, value)

        # invariant: the proof is the same if generated here again

        return proof

    def verify_non_deletion(self, proof, old_root, new_root, keys, values):
        # computing from leaves towards root. This is also important for security: we show that based on leaves
        # we reach a specific root, and intermediate hashes from the proof must not override the chains.
        def compute_forest(forest, extra, path):
            for level in reversed(range(self.depth+1)):
                extra2 = {}
                for k in extra.keys():
                    kval = extra.get(k, default)
                    parent = k[:-1]
                    sibling = k[:-1] + ('1' if k[-1] == '0' else '0')
                    siblingval = extra.get(sibling, forest.get(sibling, default))  # first extra: do not trust the proof
                    pv = hash(kval, siblingval) if k[-1] == '0' else hash(siblingval, kval)
                    # k_as_int = int(k, 2) if len(k) > 0 else 0
                    # if k[-1] == '0':
                    #     print(f"{level}: k: {k_as_int} h( {kval} {siblingval} )-> {pv}", file=sys.stderr)
                    # else:
                    #     print(f"{level}: K: {k_as_int} h( {siblingval} {kval} )-> {pv}", file=sys.stderr)
                    if parent == path:
                        return pv
                    extra2[parent] = pv
                extra = extra2
            return False

        # step 1. compute old root based on proof and 'empty' leaves in place of new batch
        p1 = {}
        for key in sorted(keys):
            p1[self.key_to_bits(key)] = self.default[0]

        r1 = compute_forest(proof, p1, '')
        if r1 != old_root:
            print(f"Non-deletion proof root mismatch: r:{r1}, oldr:{old_root}", file=sys.stderr)
            return False

        # step 2. compute new root based on proof and leaves from the batch
        p2 = {}
        for key, value in sorted(zip(keys, values)):
            p2[self.key_to_bits(key)] = value

        r2 = compute_forest(proof, p2, '')
        if r2 != new_root:
            print(f"Non-deletion proof root mismatch: r:{r2}, newr:{new_root}", file=sys.stderr)
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

    def dump_witness(self, proof, old_root, new_root, keys, values):
        witness_data = {
            "old_root": old_root,
            "new_root": new_root,
            "keys": keys,
            "values": values,
            "proof": proof,
            "depth": self.depth
        }
        return(json.dumps(witness_data, indent=4))


def main():
    depth = 16

    def to_int(aa):
        if isinstance(aa, (list, tuple)):
            return [to_int(a) for a in aa]
        elif isinstance(aa, bytes):
            return int.from_bytes(aa, byteorder='big')
        else:
            return to_int(str(aa).encode())

    def to_bytes(bb):
        return str(bb).encode()

    def pad(aa, l):
        if len(aa) > l:
            raise OverflowError("too long")
        return [f"""{a}""" for a in aa] + ["0"] * (l - len(aa))

    def js(a):
        # json strings are safer than naked bigints
        return f"""{a}"""

    smt = SparseMerkleTree(depth)

    keys = to_int([b'\x01', b'\x02', b'\x05'])
    values = to_int([b'value1', b'value2', b'value5'])
    old_root = smt.get_root()
    proof = smt.batch_insert(keys, values)
    new_root = smt.get_root()
    assert smt.verify_non_deletion(proof, old_root, new_root, keys, values)

    # keys = [b'\x03', b'\x0a', b'\x0b', b'\x0c']
    # values = [b'value3', b'value0a', b'value0b', b'value0c']
    keys = []
    values = []
    # first some pre-fillign of the tree
    for i in range(32):
        ri = random.randint(0, 2**depth-1)
        if ri in keys:
            break
        keys.append(ri)
        values.append(to_int(("Val " + str(ri)).encode()))

    proof = smt.batch_insert(keys, values)
    new_root = smt.get_root()

    keys = []
    values = []
    # this batch goes to proving
    for i in range(32):
        ri = random.randint(0, 2**depth-1)
        p = smt.key_to_bits(ri)
        if ri in keys:
            break
        keys.append(ri)
        values.append(to_int(("Val " + str(ri)).encode()))

    proof = smt.batch_insert(keys, values)
    old_root = new_root
    new_root = smt.get_root()
    assert smt.verify_non_deletion(proof, old_root, new_root, keys, values)
    print(smt.dump_witness(proof, old_root, new_root, keys, values))

if __name__ == "__main__":
    main()
