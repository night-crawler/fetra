#![no_std]

use bytemuck::{Pod, Zeroable};

#[repr(C)]
#[derive(Clone, Copy, Zeroable, Pod, Debug)]
pub struct FileAccessEvent {
    pub inode: u64,           // 8
    pub bytes: i64,           // 8

    pub tid: u32,             // 4
    pub tgid: u32,            // 4
    pub dev: u32,             // 4
    _pad0: [u8; 4],           // pad to 8-byte boundary

    pub comm: [u8; 16],       // 16

    pub s_magic: u64,         // 8
    pub i_mode: u16,          // 2
    _pad1: [u8; 6],           // pad to 8-byte boundary

    pub d_name: [u8; 256],    // 256
}
