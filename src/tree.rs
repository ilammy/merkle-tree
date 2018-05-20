// Copyright (c) 2018, ilammy
//
// Licensed under MIT license (see LICENSE in the root directory).
// This file may be copied, distributed, and modified only
// in accordance with the terms specified by the license.

use std::marker::PhantomData;

use bytes::AsBytes;
use hash::Hash;
use proof::{ExistenceProof, AnchoredHash};

pub struct MerkleTree<T> {
    layers: Vec<Vec<Hash>>,
    elements: PhantomData<T>,
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
        use hash::{hash_value, combine_hashes};

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

        return Some(ExistenceProof::from_path(merkle_path));
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
