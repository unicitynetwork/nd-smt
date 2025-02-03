import hashlib
import pprint

default = b'\x00' * 1 # 32

def dump(d):
    pprint.pp(d, width=220)

def hash(left, right):
    if left == default and right == default:
        return default
    else:
        return hashlib.sha256(left + right).digest()

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
            print(f"The leaf '{path}' is already set, but we're allowing this for testing")
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
        return format(int.from_bytes(key, 'big'), '0{}b'.format(self.depth))

    def batch_insert(self, keys, values):
        proof = {}
        # proof of consistency: collect all siblings necessary to compute root
        # based on new batch of keys
        # 'default' leaves are NOT included
        for k in self.missing_keys(keys):
            level = self.depth - len(k)
            v = self.get_node(level, k)
            if v != default:
                proof[k] = v

        # Pe    rform all insertions
        for key, value in zip(keys, values):
            self.insert(key, value)

        # invariant: the proof is the same if generated here again

        return proof

    def verify_non_deletion(self, proof, old_root, new_root, keys, values):
        def compute_forest(forest, path):
            dump(forest)
            for level in reversed(range(self.depth+1)):
                last_parent = None
                for k in sorted([key for key in forest if len(key) == level]):
                    parent = k[:-1]
                    if parent == last_parent:
                        continue
                    sibling = k[:-1] + ('1' if k[-1] == '0' else '0')
                    pv = hash(forest[k], forest.get(sibling, default)) if k[-1] == '0' else hash(forest.get(sibling, default), forest[k])
                    if parent in forest:
                        print(f"redundant parent {parent} in proof")
                        if forest[parent] != pv:
                            print(f"parent mismatch {parent}->{forest[parent]}/{pv} in proof")
                            return False
                    if parent == path:
                        return pv
                    forest[parent] = pv
                    last_parent = parent
            return False

        # step 1. compute old root based on proof and 'empty' leaves in place of new batch
        p1 = proof.copy()
        for key in keys:
            p1[self.key_to_bits(key)] = self.default[0]

        r1 = compute_forest(p1, '')
        if r1 != old_root:
            print(f"Non-deletion proof root mismatch: r:{r1}, oldr:{old_root}")
            #return False

        # step 2. compute new root based on proof and leaves from the batch
        p2 = proof.copy()
        for key, value in zip(keys, values):
            p2[self.key_to_bits(key)] = value

        r2 = compute_forest(p2, '')
        if r2 != new_root:
            print(f"Non-deletion proof root mismatch: r:{r1}, newr:{new_root}")
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
    smt = SparseMerkleTree(depth=8)

    keys = [b'\x01', b'\x02', b'\x05']
    values = [b'value1', b'value2', b'value5']
    old_root = smt.get_root()
    proof = smt.batch_insert(keys, values)
    new_root = smt.get_root()
    print(smt.verify_non_deletion(proof, old_root, new_root, keys, values))

    keys = [b'\x03', b'\x0a', b'\x0b', b'\x0c']
    values = [b'value3', b'value0a', b'value0b', b'value0c']
    proof = smt.batch_insert(keys, values)
    new_new_root = smt.get_root()
    print(smt.verify_non_deletion(proof, new_root, new_new_root, keys, values))

if __name__ == "__main__":
    main()