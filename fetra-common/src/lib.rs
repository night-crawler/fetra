#![no_std]

use bytemuck::{Pod, Zeroable};

#[repr(C)]
#[derive(Clone, Copy, Zeroable, Pod, Debug)]
pub struct FileAccessEvent {
    pub inode: u64,
    pub bytes: i64,

    pub tid: u32,
    pub tgid: u32,
    pub dev: u32,
    _pad0: [u8; 4],

    pub comm: [u8; 16],

    pub s_magic: u64,
    pub i_mode: u16,
    _pad1: [u8; 6],

    pub path: [u8; 256],
}
