use linux_raw_sys::general::*;
use num_enum::TryFromPrimitive;
use std::fmt::{Debug, Display, Formatter};
use strum_macros::AsRefStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive, AsRefStr)]
#[repr(u32)]
pub enum FileType {
    Fifo = S_IFIFO,
    CharacterDevice = S_IFCHR,
    BlockDevice = S_IFBLK,
    Directory = S_IFDIR,
    RegularFile = S_IFREG,
    Symlink = S_IFLNK,
    Socket = S_IFSOCK,

    Unknown = 0,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Triplet {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl Debug for Triplet {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        <Self as Display>::fmt(self, f)
    }
}

impl Display for Triplet {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        const MAP: [char; 4] = ['-', 'r', 'w', 'x'];
        let r = MAP[self.read as usize];
        let w = MAP[self.write as usize * 2];
        let x = MAP[self.execute as usize * 3];
        write!(f, "{r}{w}{x}")
    }
}

impl Triplet {
    pub const fn from_masks(mode: u32, read_mask: u32, write_mask: u32, exec_mask: u32) -> Self {
        Self {
            read: mode & read_mask != 0,
            write: mode & write_mask != 0,
            execute: mode & exec_mask != 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Permissions {
    pub owner: Triplet,
    pub group: Triplet,
    pub others: Triplet,
    pub setuid: bool,
    pub setgid: bool,
    pub sticky: bool,
}

impl From<u16> for Permissions {
    fn from(value: u16) -> Self {
        let value = value as u32;
        Self {
            owner: Triplet::from_masks(value, S_IRUSR, S_IWUSR, S_IXUSR),
            group: Triplet::from_masks(value, S_IRGRP, S_IWGRP, S_IXGRP),
            others: Triplet::from_masks(value, S_IROTH, S_IWOTH, S_IXOTH),
            setuid: value & S_ISUID != 0,
            setgid: value & S_ISGID != 0,
            sticky: value & S_ISVTX != 0,
        }
    }
}
