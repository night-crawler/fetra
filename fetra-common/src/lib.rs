#![no_std]

use bytemuck::{Pod, Zeroable};

#[repr(u32)] 
#[derive(Clone, Copy, Zeroable, Debug)]
pub enum EventType {
    MmapRead = 0,
    MmapWrite = 1,
    NullPage = 3,
    
    VfsRead = 20,
    VfsWrite = 30,
    
    VfsReadv = 40,
    VfsWritev = 50,
    
}

unsafe impl bytemuck::Pod for EventType {}

#[repr(C)]
#[derive(Clone, Copy, Zeroable, Pod, Debug)]
pub struct FileAccessEvent {
    pub inode: u64,
    pub bytes: u64,

    pub tid: u32,
    pub tgid: u32,
    pub dev: u32,
    pub event_type: EventType,

    pub comm: [u8; 16],

    pub s_magic: u64,
    pub i_mode: u16,
    _pad1: [u8; 6],

    pub path: [u8; 256],
}
