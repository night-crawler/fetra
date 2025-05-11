//! Utilities to pretty‑print `FileAccessEvent`s in an `ls -lah`‑inspired style
//! keeping special files (sockets, pipes, char/block devices …) readable and
//! showing resolved device names when possible.

use linux_raw_sys::general::{
    ANON_INODE_FS_MAGIC, BPF_FS_MAGIC, BTRFS_SUPER_MAGIC, CGROUP2_SUPER_MAGIC, DEBUGFS_MAGIC,
    DEVPTS_SUPER_MAGIC, HUGETLBFS_MAGIC, NSFS_MAGIC, OVERLAYFS_SUPER_MAGIC, PIPEFS_MAGIC,
    PROC_SUPER_MAGIC, RAMFS_MAGIC, SECURITYFS_MAGIC, SELINUX_MAGIC, SMACK_MAGIC, SOCKFS_MAGIC,
    SYSFS_MAGIC, S_IFBLK, S_IFCHR, S_IFDIR, S_IFIFO, S_IFLNK, S_IFMT, S_IFREG, S_IFSOCK,
    TMPFS_MAGIC, TRACEFS_MAGIC,
};
use std::ffi::{c_char, CStr};
use std::fs;

use fetra_common::FileAccessEvent;
use libc::{major, minor};

fn get_inode_type_desc(magic: u64, mode: u16) -> String {
    let magic_desc = match magic as u32 {
        ANON_INODE_FS_MAGIC => "anon_inode",
        PIPEFS_MAGIC => "pipe",
        SOCKFS_MAGIC => "socket",
        TMPFS_MAGIC => "tmpfs",
        DEVPTS_SUPER_MAGIC => "devpts",
        PROC_SUPER_MAGIC => "proc",
        SYSFS_MAGIC => "sysfs",
        DEBUGFS_MAGIC => "debugfs",
        SECURITYFS_MAGIC => "securityfs",
        CGROUP2_SUPER_MAGIC => "cgroup2",
        BPF_FS_MAGIC => "bpf",
        HUGETLBFS_MAGIC => "hugetlbfs",
        NSFS_MAGIC => "ns",
        OVERLAYFS_SUPER_MAGIC => "overlay",
        RAMFS_MAGIC => "ramfs",
        SELINUX_MAGIC => "selinux",
        SMACK_MAGIC => "smack",
        TRACEFS_MAGIC => "tracefs",
        BTRFS_SUPER_MAGIC => "btrfs",
        _ => "",
    };

    if !magic_desc.is_empty() && magic != ANON_INODE_FS_MAGIC as u64 {
        return magic_desc.to_string();
    }

    let file_type = (mode as u32) & S_IFMT;
    let mode_desc = match file_type {
        S_IFIFO => "fifo",
        S_IFCHR => "char_dev",
        S_IFDIR => "dir",
        S_IFBLK => "block_dev",
        S_IFREG => {
            if magic == ANON_INODE_FS_MAGIC as u64 {
                "anon_inode_file"
            } else {
                "regular_file"
            }
        }
        S_IFLNK => "symlink",
        S_IFSOCK => "socket",
        _ => "",
    };

    if !mode_desc.is_empty() {
        if magic == ANON_INODE_FS_MAGIC as u64 && mode_desc != "socket" {
            format!("anon_inode:[{mode_desc}]")
        } else {
            mode_desc.to_string()
        }
    } else if magic == ANON_INODE_FS_MAGIC as u64 {
        "anon_inode:[unknown]".to_string()
    } else {
        format!("magic:0x{magic:x}")
    }
}

fn mode_to_string(mode: u16) -> String {
    let mut out = String::with_capacity(10);

    // first char – file‑type indicator
    let typ = match (mode as u32) & S_IFMT {
        S_IFSOCK => 's',
        S_IFLNK => 'l',
        S_IFREG => '-',
        S_IFBLK => 'b',
        S_IFDIR => 'd',
        S_IFCHR => 'c',
        S_IFIFO => 'p',
        _ => '?',
    };
    out.push(typ);

    // nine permission bits
    for shift in (0..9).rev().step_by(3) {
        let r = 1 << (shift + 2);
        let w = 1 << (shift + 1);
        let x = 1 << shift;

        out.push(if (mode & r) != 0 { 'r' } else { '-' });
        out.push(if (mode & w) != 0 { 'w' } else { '-' });
        out.push(if (mode & x) != 0 { 'x' } else { '-' });
    }
    out
}

/// Human‑friendly (IEC) byte sizes, used for regular files.
fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 7] = ["B", "K", "M", "G", "T", "P", "E"];
    let mut val = bytes as f64;
    let mut idx = 0usize;
    while val >= 1024.0 && idx < UNITS.len() - 1 {
        val /= 1024.0;
        idx += 1;
    }
    if idx == 0 {
        format!("{val:.0}{}", UNITS[idx])
    } else {
        format!("{val:.1}{}", UNITS[idx])
    }
}

/// Extract major/minor numbers from the raw `dev` field.
fn major_minor(dev: u32) -> (u32, u32) {
    let d = dev as libc::dev_t;
    (major(d), minor(d))
}

/// Best‑effort translation of a `(major,minor)` pair into a `/dev/<node>` name.
fn dev_name_from_dev(dev: u32) -> Option<String> {
    let (maj, min) = major_minor(dev);
    let path = format!("/sys/dev/block/{maj}:{min}/uevent");
    if let Ok(content) = fs::read_to_string(&path) {
        for line in content.lines() {
            if let Some(name) = line.strip_prefix("DEVNAME=") {
                return Some(name.to_string());
            }
        }
    }
    None
}

pub trait EventExt {
    fn process(self) -> Result<(), String>;
}

impl EventExt for FileAccessEvent {
    fn process(self) -> Result<(), String> {
        let comm = unsafe { CStr::from_ptr(self.comm.as_ptr() as *const c_char) };
        let comm = comm.to_string_lossy();
        let path = unsafe { CStr::from_ptr(self.path.as_ptr() as *const c_char) };
        let path = path.to_string_lossy();

        let perms = mode_to_string(self.i_mode);
        let inode_desc = get_inode_type_desc(self.s_magic, self.i_mode);

        let (maj, min) = major_minor(self.dev);
        let dev_display = dev_name_from_dev(self.dev).unwrap_or_else(|| format!("{maj},{min}"));

        let size_field = match perms.chars().next() {
            Some('c') | Some('b') => format!("{maj},{min}"),
            Some('s') | Some('p') => "-".to_string(),
            _ => human_size(self.bytes),
        };

        println!(
            "{typ:<10?} {perms} {tgid:<10}:{tid:<10} {comm:<16} {size:<8} {dev:<10} {inode:<18} {path}",
            typ=self.event_type,
            tgid = self.tgid,
            tid = self.tid,
            size = size_field,
            dev = dev_display,
            inode = inode_desc,
            path = path,
        );

        Ok(())
    }
}
