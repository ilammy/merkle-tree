// Copyright (c) 2018, ilammy
//
// Licensed under MIT license (see LICENSE in the root directory).
// This file may be copied, distributed, and modified only
// in accordance with the terms specified by the license.

type Element = Vec<u8>;
type Hash = Vec<u8>;

pub struct MerkleTree {
    layers: Vec<Vec<Hash>>,
    elements: Vec<Element>,
}

pub struct ExistenceProof {
    merkle_path: Vec<AnchoredHash>,
}

struct AnchoredHash {
    layer: usize,
    index: usize,
    hash: Hash,
}

impl MerkleTree {
    pub fn root_hash(&self) -> Option<&Hash> {
        self.layers.last().map(|hashes| &hashes[0])
    }

    pub fn make_empty() -> MerkleTree {
        MerkleTree {
            layers: vec![],
            elements: vec![],
        }
    }

    pub fn from(elements: Vec<Element>) -> MerkleTree {
        // Empty list is a special case. Deal with it here.
        if elements.is_empty() {
            return MerkleTree::make_empty();
        }

        // In this case we can compute the tree faster than making an empty one and inserting
        // elements into it one by one. We make fewer intermediate modifications this way.
        let mut layers: Vec<Vec<Hash>> = Vec::new();

        // Compute hashes for all elements of the collection and collect them into a list.
        // These nodes will be leaves of the tree, forming its bottom layer.
        layers.push(elements.iter().map(|e| hash_value(e)).collect());

        // Now combine adjacent tree nodes, layer by layer, to compute intermediate hashes.
        // Do this until we are left with a single node--the root one.
        while layers.last().unwrap().len() > 1 {
            let next_layer = layers.last().unwrap()
                .as_slice()
                .chunks(2)
                .map(|pair|
                    // If the layer contains an odd number of elements then Merkle tree
                    // duplicates the hash of the last element.
                    if pair.len() == 2 {
                        combine_hashes(&pair[0], &pair[1])
                    } else {
                        combine_hashes(&pair[0], &pair[0])
                    }
                )
                .collect();

            layers.push(next_layer);
        }

        return MerkleTree { layers, elements };
    }

    pub fn prove_existence(&self, index: usize) -> Option<ExistenceProof> {
        let mut merkle_path = Vec::new();

        let mut current_layer = 0;
        let mut current_index = index;

        // We start at the bottom of the tree and trace our way to its top,
        // remembering all nodes which are required for existence verification.
        while self.valid_coords(current_layer, current_index) {
            let sibling_index = self.sibling_index(current_layer, current_index);
            merkle_path.push(self.anchored_hash(current_layer, sibling_index));

            current_layer += 1;
            current_index /= 2;
        }

        // Path may be empty if the index was invalid, including the case of an empty tree.
        if merkle_path.is_empty() {
            return None;
        }

        // Drop the last element (root node). It is always added to the path,
        // but it is not necessary for existence verification.
        merkle_path.pop();

        return Some(ExistenceProof { merkle_path });
    }

    fn valid_coords(&self, layer: usize, index: usize) -> bool {
        (layer < self.layers.len()) && (index < self.layers[layer].len())
    }

    fn sibling_index(&self, layer: usize, index: usize) -> usize {
        let layer_len = self.layers[layer].len();
        // Last node of a layer with odd number of nodes does not have siblings.
        // This node should be duplicated in the hash, return its own index.
        if (layer_len % 2 != 0) && (index == layer_len - 1) {
            return index;
        }
        // Left nodes have even indices, right nodes have odd ones. Swap them.
        if index % 2 == 0 {
            return index + 1;
        } else {
            return index - 1;
        }
    }

    fn anchored_hash(&self, layer: usize, index: usize) -> AnchoredHash {
        AnchoredHash {
            layer,
            index,
            hash: self.layers[layer][index].clone(),
        }
    }
}

// TODO: replace this with an actual hash function
// TODO: make value generic
fn hash_value(value: &Element) -> Hash {
    value.clone()
}

fn combine_hashes(lhs: &Hash, rhs: &Hash) -> Hash {
    let mut vec = Vec::new();
    vec.extend_from_slice(lhs);
    vec.extend_from_slice(rhs);
    return vec;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_tree() {
        let tree = MerkleTree::make_empty();

        assert_eq!(tree.root_hash(), None);
    }

    #[test]
    fn from_list_empty() {
        let tree = MerkleTree::from(vec![]);

        assert_eq!(tree.root_hash(), None);
    }

    #[test]
    fn from_list_one() {
        let tree = MerkleTree::from(vec![vec![1]]);

        assert_eq!(tree.root_hash().unwrap(), &[1]);
    }

    #[test]
    fn from_list_even() {
        //    .
        //   / \
        //  .   .
        // / \ / \
        // 1 2 3 4
        let tree = MerkleTree::from(vec![vec![1], vec![2], vec![3], vec![4]]);

        assert_eq!(tree.root_hash().unwrap(), &[1, 2, 3, 4]);
    }

    #[test]
    fn from_list_odd() {
        //      .
        //     / \
        //    .   :
        //   / \   \
        //  .   .   :
        // / \ / \ /
        // 1 2 3 4 5
        let tree = MerkleTree::from(vec![vec![1], vec![2], vec![3], vec![4], vec![5]]);

        assert_eq!(tree.root_hash().unwrap(), &[1, 2, 3, 4, 5, 5, 5, 5]);
    }
}
