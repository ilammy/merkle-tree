// Copyright (c) 2018, ilammy
//
// Licensed under MIT license (see LICENSE in the root directory).
// This file may be copied, distributed, and modified only
// in accordance with the terms specified by the license.

use sha2::{Sha256, Digest};

use bytes::AsBytes;

pub type Hash = Vec<u8>;

pub fn hash_value<T: AsBytes>(value: &T) -> Hash {
    let mut hasher = Sha256::default();
    hasher.input(value.as_bytes().as_slice());
    return hasher.result().to_vec();
}

pub fn combine_hashes(lhs: &Hash, rhs: &Hash) -> Hash {
    let mut hasher = Sha256::default();
    hasher.input(lhs);
    hasher.input(rhs);
    return hasher.result().to_vec();
}
