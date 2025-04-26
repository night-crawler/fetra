use anyhow::Context as _;
use aya::maps::RingBuf;
use aya::{programs::FEntry, Btf, EbpfLoader};
use fetra_common::Event;
#[rustfmt::skip]
use log::{debug, warn};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let pid = unsafe {
        libc::getpid()
    } as u32;

    let parent_pid = unsafe {
        libc::getppid()
    } as u32;


    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    let mut loader = EbpfLoader::new();
    let btf = Btf::from_sys_fs().ok();
    loader
        .btf(btf.as_ref())
        .set_global("FILTER_TGID", &parent_pid, true);

    let mut ebpf = loader.load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/fetra"
    )))?;

    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!("failed to initialize eBPF logger: {e}");
    }

    let btf = Btf::from_sys_fs().context("BTF from sysfs")?;
    let program: &mut FEntry = ebpf.program_mut("handle_write").unwrap().try_into()?;
    program.load("vfs_write", &btf)?;
    program.attach()?;

    let mut ring_buf = RingBuf::try_from(ebpf.map_mut("EVENTS").unwrap())?;

    loop {
        while let Some(item) = ring_buf.next() {
            let e = bytemuck::from_bytes::<Event>(&item);
            if e.pid == pid as u32 || e.pid == parent_pid as u32 {
                continue;
            }
            let p = format!("/proc/{}/fd/{}",e.tgid, e.inode);
            println!("{p}, ppid={parent_pid}, pid={pid}");
            // let path = std::fs::read_link(&p)
            //     .unwrap_or_else(|_| "<unknown>".into());
            // println!("{path:?}, {e:?}");
            // println!("Received: {:?}", e);
        }
    }
}
