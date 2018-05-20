// Copyright (c) 2018, ilammy
//
// Licensed under MIT license (see LICENSE in the root directory).
// This file may be copied, distributed, and modified only
// in accordance with the terms specified by the license.

extern crate sha2;

use std::marker::PhantomData;

use sha2::{Sha256, Digest};

type Hash = Vec<u8>;

pub struct MerkleTree<T> {
    layers: Vec<Vec<Hash>>,
    elements: PhantomData<T>,
}

pub struct ExistenceProof {
    merkle_path: Vec<AnchoredHash>,
}

pub trait AsBytes {
    fn as_bytes(&self) -> Vec<u8>;
}

impl<T> AsBytes for T where T: AsRef<[u8]> {
    fn as_bytes(&self) -> Vec<u8> {
        self.as_ref().to_vec()
    }
}

enum AnchoredHash {
    Left(Hash),
    Right(Hash),
}

impl<T> MerkleTree<T> {
    pub fn root_hash(&self) -> Option<&Hash> {
        self.layers.last().map(|hashes| &hashes[0])
    }

    pub fn make_empty() -> MerkleTree<T> {
        MerkleTree {
            layers: vec![],
            elements: PhantomData,
        }
    }

    pub fn from<I>(collection: I) -> MerkleTree<T>
        where I: IntoIterator<Item=T>,
              T: AsBytes
    {
        // Compute hashes for all elements of the collection and collect them into a list.
        // These nodes will be leaves of the tree, forming its bottom layer.
        let bottom_layer: Vec<_> = collection
            .into_iter()
            .map(|ref e| hash_value(e))
            .collect();

        // Empty list is a special case. Deal with it here.
        if bottom_layer.is_empty() {
            return MerkleTree::make_empty();
        }

        let mut layers = Vec::new();

        layers.push(bottom_layer);

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

        return MerkleTree { layers, elements: PhantomData };
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
        let hash = self.layers[layer][index].clone();

        if index % 2 == 0 {
            AnchoredHash::Left(hash)
        } else {
            AnchoredHash::Right(hash)
        }
    }
}

impl ExistenceProof {
    pub fn is_valid<T: AsBytes>(&self, element: &T, root_hash: &Hash) -> bool {
        let mut hash = hash_value(element);

        // Combine hashes from the Merkle path with the element hash.
        // In the end we should get the root hash.
        for next in &self.merkle_path {
            match next {
                AnchoredHash::Left(next_hash) => {
                    hash = combine_hashes(&next_hash, &hash);
                }
                AnchoredHash::Right(next_hash) => {
                    hash = combine_hashes(&hash, &next_hash);
                }
            }
        }

        return &hash == root_hash;
    }
}

fn hash_value<T: AsBytes>(value: &T) -> Hash {
    let mut hasher = Sha256::default();
    hasher.input(value.as_bytes().as_slice());
    return hasher.result().to_vec();
}

fn combine_hashes(lhs: &Hash, rhs: &Hash) -> Hash {
    let mut hasher = Sha256::default();
    hasher.input(lhs);
    hasher.input(rhs);
    return hasher.result().to_vec();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn as_hex_str(bytes: &[u8]) -> String {
        bytes.iter()
             .map(|byte| format!("{:02x}", byte))
             .collect()
    }

    #[test]
    fn empty_tree() {
        let tree = MerkleTree::<&[u8]>::make_empty();

        assert_eq!(tree.root_hash(), None);
    }

    #[test]
    fn from_list_empty() {
        let tree = MerkleTree::from(&[] as &[&[u8]]);

        assert_eq!(tree.root_hash(), None);
    }

    #[test]
    fn from_list_one() {
        // .
        // |
        // 1
        let tree = MerkleTree::from(&[b"1"]);

        assert_eq!(as_hex_str(tree.root_hash().unwrap()),
            "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b");
    }

    #[test]
    fn from_list_even() {
        //    .
        //   / \
        //  .   .
        // / \ / \
        // 1 2 3 4
        let tree = MerkleTree::from(&[b"1", b"2", b"3", b"4"]);

        assert_eq!(as_hex_str(tree.root_hash().unwrap()),
            "cd53a2ce68e6476c29512ea53c395c7f5d8fbcb4614d89298db14e2a5bdb5456");
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
        let tree = MerkleTree::from(&[b"1", b"2", b"3", b"4", b"5"]);

        assert_eq!(as_hex_str(tree.root_hash().unwrap()),
            "0abb51d233d9b6172ff6fcb56b4ef172f550da4cb15aa328ebf43751288b8011");
    }

    #[test]
    fn validate_one() {
        let tree = MerkleTree::from(&[b"1"]);
        let root_hash = tree.root_hash().expect("root hash");

        let proof = tree.prove_existence(0).expect("existence proof");

        assert!(proof.is_valid(b"1", &root_hash));
    }

    #[test]
    fn validate_multiple() {
        let elements = &[b"1", b"2", b"3", b"4", b"5", b"6", b"7", b"8", b"9", b"A", b"B"];

        let tree = MerkleTree::from(&elements[..]);
        let root_hash = tree.root_hash().expect("root hash");

        for (index, element) in elements.iter().enumerate() {
            let proof = tree.prove_existence(index).expect("existence proof");

            assert!(proof.is_valid(element, &root_hash));
        }
    }

    #[test]
    fn empty_tree_has_no_root() {
        let tree = MerkleTree::<&[u8]>::make_empty();

        assert!(tree.root_hash().is_none());
    }

    #[test]
    fn invalid_indices_have_no_proofs() {
        let tree = MerkleTree::from(&[b"A", b"B"]);

        assert!(tree.prove_existence(2).is_none());
        assert!(tree.prove_existence(9000).is_none());
    }
}
