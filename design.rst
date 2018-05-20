~~~~~~~~~~~~
Design notes
~~~~~~~~~~~~

Intent
======

**Merkle tree** is intended to be an efficient way to verify contents of large
data structures. Let's say you have a list of elements and want to verify its
integrity (i.e., that all elements have expected values and are in the expected
order). You can compute a *hash sum* of the while list and compare it to the
reference value. If they match then the list is OK. However, this 1) requires
you to have the whole list available, 2) does not tell you which elements
are incorrect if the hash sum does not match.

A Merkle tree allows integrity verification on per element basis. With it you
can retrieve the list partially and efficiently verify that each list element
has an expected value and is located in an expected position in the list.
This is achieved by clever combination of hash computation on list elements::

                          R = hash(H5 + H6)                             root node
                  ,--------------^-------------.
                 /                              \
        H5 = hash(H1 + H2)                  H6 = hash(H3 + H4)          branch nodes
         /             \                     /             \
        /               \                   /               \
  H1 = hash("1")    H2 = hash("2")    H3 = hash("3")    H4 = hash("4")  leaf nodes
       |                 |                 |                 |
  --------------------------------------------------------------------
       |                 |                 |                 |
    [ "1" ,             "2" ,             "3" ,             "4" ]       the list

The *root hash* allows verification of the list content as a whole. Once you
get the whole list you can compute the root hash and see if it matches the
expected value. Branch hashes can be extracted and used to prove that an
element with a particular hash exists in the list at a given position.

Goals
-----

Here we implement three main algorithms on Merkle trees:

* **constructing a tree** — given a list of elements, construct the Merkle
  tree for them, providing the *root hash*

* **constructing proof-of-existence** — given a Merkle tree and element index,
  extract the hashes necessary to verify that the element exists in the tree

* **verifying proof-of-existence** — given an element, the expected root hash,
  and the 'proof' hashes, reconstruct the root hash to verify the proof

Data structures
===============

Merkle tree
-----------

Initially I wanted to use a proper *tree* as the underlying data structure,
with ``Option<Rc<RefCell<_>>>`` as the main type of references between nodes.
However, such approach quickly turned out to be burdensome as it does not allow
to keep around references to the nodes. With ``RefCell`` the lifetime of the
node reference is always shorter than the reference to the whole tree. You can
return an ``Rc`` reference to the node, but it is also somewhat unwieldy.

Using proper tree structure has its merits. For example, it allows to implement
*persistent data structures* more or less efficiently. However, with Merkle
tree one is usually interested only in the current state of the data so mutable
state should be a better for the use case.

After quickly exploring an alternative implementation using *arenas*, I settled
upon an interesting indirect representation of the tree. It explicitly stores
the tree layers in nested vectors, resulting in the following structure::

    [
        ["1", "2", "3", "4", "5", "6", "7"],    //    "1" "2" "3" "4" "5" "6" "7"
                                                //      \ /     \ /     \ /     \
        ["1+2", "3+4", "5+6", "7+7"],           //     "1+2"   "3+4"   "5+6"   "7+7"
                                                //        \     /         \     /
        ["(1+2)+(3+4)", "(5+6)+(7+7)"],         //     "(1+2)+(3+4)"   "(5+6)+(7+7)"
                                                //                \     /
        ["(((1+2)+(3+4))+((5+6)+(7+7)))"],      //    "(((1+2)+(3+4))+((5+6)+(7+7)))"
    ]

It has the following useful properties:

* length of the outer vector indicates the tree height
* the first layer is the bottom layer, containing all leaf nodes
* the last layer always contains exactly *one node* – the root node
  which contains the Merkle root hash
* layers in the middle contain all branches with intermediate hashes

It is also worth noting that the position of each node can be represented
using a pair (*layer*, *index*)::

    [
        ["0-0", "0-1", "0-2", "0-3", "0-4", "0-5", "0-6"],
        ["1-0", "1-1", "1-2", "1-3"],
        ["2-0", "2-1"],
        ["3-0"],
    ]

This layer–index coordinate system also has some useful properties:

* left child node have even indices, right ones have odd indices
* coordinates remain valid and still point to the same nodes
  if new nodes are *appended* to the tree
* node ``(n, m)`` combines hashes of ``(n-1, 2*m)`` and ``(n-1, 2*m + 1)``

Predictability of the number of nodes in the layer allows to store all of them
in a single vector (with some index offset trickery), but we use nested vectors
for the sake of simplicity.

Existence proof
---------------

In order to prove existence of an element *E* in the tree we need to provide
all intermediate hashes which are needed to compute the root hash.
For example::

    0-1     0-2     0-3     0-4   [ 0-5 ]  (0-6)        0-7
     |       |       |       |       |       |           |
     +- 1-0 -+       +- 1-1 -+       +- 1-2 -+        [ 1-3 ]
         |               |               |               |
         +----[ 2-0 ]----+               +----- 2-1 -----+
                 |                               |
                 +------------- 3-0 -------------+

Here to prove that element ``0-6`` exists in the tree we need to provide
the following list of intermediate hashes: ``0-5``, ``1-3``, ``2-0``.
This allows us to compute the root node hash:

* H(1-2) = H(**H(0-5)** + H(0-6))
* H(2-1) = H(H(1-2) + **H(1-3)**)
* H(3-0) = H(**H(2-0)** + H(2-1))

If the computed root hash matches the expected one then the element does
exist in the tree. Otherwise either the element, or the proof is damaged.

The intermediate nodes are in fact *siblings* of the nodes along the path
from the verified node to the root node. In the above case this path is
``0-6`` – ``1-2`` – ``2-1`` – ``3-0``.

Note that the root hash computation is iterative and similar to
*Horner's method*, thus we do not need to store the exact coordinates
of the intermediate nodes. We just need to order them from bottom to top
and compute the hash in that order.

We also need to store the *direction* of the traversal along with the hash
because H(A + B) is not the same as H(B + A). Thus the final representation
of the existence proof looks like this::

    [Left(0-5), Right(1-3), Left(2-0)] -- proves existence of 0-6

(Optionally it can include the element itself.)

There is also a special case of *duplicated* nodes. Merkle tree duplicates
hashes of nodes without siblings, as if there was a phantom sibling node
with the same value. For example, H(1-3) = H(0-7) + H(0-7). In this case
the existence proof will contain the hash of the leaf node itself::

    [Left(0-7), Left(1-2), Left(2-0)] -- proves existence of 0-7

Hash function
=============

I used SHA-256 as an example. The implementation is taken from ``sha2``
crate.

We should not use the standard ``Hash`` trait as Merkle tree requires
a *cryptographic* hash function. Rust uses SipHash as a default which
is not crypographically strong.

Efficiency
==========

This tree representation requries O(2N) memory to store hashes for N elements
(with some minimal overhead on ``Vec`` bookkeeping). Proofs of existence
require O(log2 N) memory for hashes of the sibling nodes along the Merkle path.

A tree can be constructed in O(N log2 N) time from existing elements.
Constructing and verifying a proof of existence requires O(log2 N) time.

Testing
=======

There are some trivial tests which verify root hash computation and that proofs
of existence really prove existence of the elements in the tree. However, the
test suite currently lacks *negative cases* (where the tree, the root hash,
the element, or the proof of existence get damaged and should not agree).

There are no benchmarks or any other performance testing.

Drawbacks
=========

The tree keeps *all* hashes in memory so it probably will not scale well
for large amounts of leaf nodes. Linear growth is not that bad, but the
Internet suggests that there are more compact representations.

Inserting a new node in the middle of the leaf list is very tricky with the
chosen representation. It is much easier to *append* a node to the end of
the leaf list.

The current implementation does not contain a method for appending new nodes.
It operates only on the element list provided during tree construction.
