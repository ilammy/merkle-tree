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
