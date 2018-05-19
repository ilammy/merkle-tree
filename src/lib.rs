// Copyright (c) 2018, ilammy
//
// Licensed under MIT license (see LICENSE in the root directory).
// This file may be copied, distributed, and modified only
// in accordance with the terms specified by the license.

use std::cell::{RefCell};
use std::rc::{Rc, Weak};

pub struct MerkleTree {
    root: Option<Rc<RefCell<Node>>>,
}

impl MerkleTree {
    pub fn root_hash(&self) -> Option<Vec<u8>> {
        self.root.as_ref().map(|node| node.borrow().hash.clone())
    }

    pub fn make_empty() -> MerkleTree {
        MerkleTree {
            root: None,
        }
    }

    pub fn from<I: IntoIterator<Item=Vec<u8>>>(collection: I) -> MerkleTree {
        // In this case we can compute the tree faster than making an empty one and inserting
        // elements into it one by one. We make fewer intermediate modifications this way.
        //
        // Compute hashes for all elements of the collection and collect them into a list.
        // These nodes will be leaves of the tree, forming its bottom layer.
        let mut layer: Vec<_> = collection.into_iter().map(|e| Node::new_value_leaf(e)).collect();

        // Now combine adjacent tree nodes, layer by layer, to compute intermediate hashes.
        // Do this until we are left with a single node in our work list--the root one.
        while layer.len() > 1 {
            let next_layer = layer
                .chunks(2)
                .map(|pair|
                    if pair.len() == 2 {
                        Node::new_double_branch(&pair[0], &pair[1])
                    } else {
                        Node::new_single_branch(&pair[0])
                    }
                )
                .collect();

            layer = next_layer;
        }

        // Now we have the final layer with only one root node.
        // It may also be empty if the collection is empty.
        MerkleTree {
            root: layer.first().map(|node| node.clone()),
        }
    }
}

// TODO: replace this with an actual hash function
// TODO: make value generic
fn hash_value(value: &Vec<u8>) -> Vec<u8> {
    value.clone()
}

fn combine_hashes(lhs: &[u8], rhs: &[u8]) -> Vec<u8> {
    let mut vec = Vec::new();
    vec.extend_from_slice(lhs);
    vec.extend_from_slice(rhs);
    return vec;
}

struct Node {
    hash: Vec<u8>,
    parent: Option<Weak<RefCell<Node>>>,
    payload: Payload,
}

enum Payload {
    LeafHashOnly,
    LeafValue {
        value: Vec<u8>,
    },
    BranchDouble {
        lhs: Rc<RefCell<Node>>,
        rhs: Rc<RefCell<Node>>,
    },
    BranchSingle {
        lhs: Rc<RefCell<Node>>,
    },
}

impl Node {
    fn new_value_leaf(value: Vec<u8>) -> Rc<RefCell<Node>> {
        Rc::new(RefCell::new(
            Node {
                hash: hash_value(&value),
                parent: None,
                payload: Payload::LeafValue {
                    value: value,
                },
            }
        ))
    }

    fn new_hash_leaf(hash: Vec<u8>) -> Rc<RefCell<Node>> {
        Rc::new(RefCell::new(
            Node {
                hash: hash,
                parent: None,
                payload: Payload::LeafHashOnly,
            }
        ))
    }

    fn new_double_branch(lhs: &Rc<RefCell<Node>>, rhs: &Rc<RefCell<Node>>) -> Rc<RefCell<Node>> {
        let node = Rc::new(RefCell::new(
            Node {
                hash: combine_hashes(&lhs.borrow().hash, &rhs.borrow().hash),
                parent: None,
                payload: Payload::BranchDouble {
                    lhs: lhs.clone(),
                    rhs: rhs.clone(),
                },
            }
        ));

        lhs.borrow_mut().parent = Some(Rc::downgrade(&node));
        rhs.borrow_mut().parent = Some(Rc::downgrade(&node));

        return node;
    }

    fn new_single_branch(lhs: &Rc<RefCell<Node>>) -> Rc<RefCell<Node>> {
        let node = Rc::new(RefCell::new(
            Node {
                // Hash is duplicated for nodes with a single child.
                hash: combine_hashes(&lhs.borrow().hash, &lhs.borrow().hash),
                parent: None,
                payload: Payload::BranchSingle {
                    lhs: lhs.clone(),
                },
            }
        ));

        lhs.borrow_mut().parent = Some(Rc::downgrade(&node));

        return node;
    }
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

        assert_eq!(tree.root_hash().unwrap(), vec![1]);
    }

    #[test]
    fn from_list_even() {
        //    .
        //   / \
        //  .   .
        // / \ / \
        // 1 2 3 4
        let tree = MerkleTree::from(vec![vec![1], vec![2], vec![3], vec![4]]);

        assert_eq!(tree.root_hash().unwrap(), vec![1, 2, 3, 4]);
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

        assert_eq!(tree.root_hash().unwrap(), vec![1, 2, 3, 4, 5, 5, 5, 5]);
    }
}
