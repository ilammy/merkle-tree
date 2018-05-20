// Copyright (c) 2018, ilammy
//
// Licensed under MIT license (see LICENSE in the root directory).
// This file may be copied, distributed, and modified only
// in accordance with the terms specified by the license.

use bytes::AsBytes;
use hash::Hash;

pub struct ExistenceProof {
    merkle_path: Vec<AnchoredHash>,
}

pub enum AnchoredHash {
    Left(Hash),
    Right(Hash),
}

impl ExistenceProof {
    pub fn from_path(merkle_path: Vec<AnchoredHash>) -> ExistenceProof {
        ExistenceProof { merkle_path }
    }

    pub fn is_valid<T: AsBytes>(&self, element: &T, root_hash: &Hash) -> bool {
        use hash::{hash_value, combine_hashes};

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
