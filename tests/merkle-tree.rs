// Copyright (c) 2018, ilammy
//
// Licensed under MIT license (see LICENSE in the root directory).
// This file may be copied, distributed, and modified only
// in accordance with the terms specified by the license.

extern crate merkle_tree;

use merkle_tree::{MerkleTree};

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
