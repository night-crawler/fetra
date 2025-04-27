#![no_std]

use bytemuck::{Pod, Zeroable};

#[repr(C)]
#[derive(Clone, Copy, Zeroable, Pod, Debug)]
pub struct FileAccessEvent {
    pub inode: u64,
    pub bytes: i64,

    pub tid:  u32,
    pub tgid: u32,
    pub dev:  u32,

    pub comm: [u8; 16],

    pub _pad: u32,
}
