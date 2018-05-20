// Copyright (c) 2018, ilammy
//
// Licensed under MIT license (see LICENSE in the root directory).
// This file may be copied, distributed, and modified only
// in accordance with the terms specified by the license.

pub trait AsBytes {
    fn as_bytes(&self) -> Vec<u8>;
}

impl<T> AsBytes for T where T: AsRef<[u8]> {
    fn as_bytes(&self) -> Vec<u8> {
        self.as_ref().to_vec()
    }
}
