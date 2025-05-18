use crate::process::event_ext::EventExt;
use crate::types;
use fetra_common::FileAccessEvent;
use metrics::Label;
use moka::future::Cache;
use std::sync::Arc;
use std::time::Duration;
use crate::init::MachineInfo;

pub struct Aggregator {
    cmd_name_by_tgid: Cache<u32, Arc<str>>,
    device_name_by_dev: Cache<u32, Arc<str>>,
    fs_type_by_magic: Cache<u64, Arc<str>>,
    file_type_by_mode: Cache<u32, Arc<str>>,
    machine_info: MachineInfo
}

impl Aggregator {
    pub fn new(machine_info: MachineInfo) -> Self {
        Self {
            machine_info,
            cmd_name_by_tgid: Cache::builder()
                .max_capacity(10000)
                .time_to_idle(Duration::from_secs(5))
                .time_to_live(Duration::from_secs(10))
                .build(),
            device_name_by_dev: Cache::builder()
                .max_capacity(100)
                .time_to_idle(Duration::from_secs(5))
                .time_to_live(Duration::from_secs(10))
                .build(),
            fs_type_by_magic: Cache::builder()
                .max_capacity(100)
                .time_to_idle(Duration::from_secs(5))
                .time_to_live(Duration::from_secs(10))
                .build(),
            file_type_by_mode: Cache::builder()
                .max_capacity(100)
                .time_to_idle(Duration::from_secs(5))
                .time_to_live(Duration::from_secs(10))
                .build(),
        }
    }
    pub async fn process_event(&self, event: &FileAccessEvent) -> Result<(), types::Error> {
        let labels = self.get_labels(event).await;
        metrics::counter!("io", labels).increment(event.bytes);
        Ok(())
    }

    async fn get_labels(&self, event: &FileAccessEvent) -> Vec<Label> {
        let path = event.path();
        let cmd = self.get_cmd(event).await;
        let dev_name = self.get_device_name(event).await;
        let fs_type = self.get_fs_type(event).await;
        let file_type = self.get_file_type(event).await;
        let perms = event.perms();
        [
            Label::new("path", path.to_string()),
            Label::new("cmd", cmd),
            Label::new("dev_name", dev_name),
            Label::new("fs_type", fs_type),
            Label::new("file_type", file_type),
            Label::new("perms_group", perms.group.to_string()),
            Label::new("perms_owner", perms.owner.to_string()),
            Label::new("perms_others", perms.others.to_string()),
            Label::new("setuid", perms.setuid.to_string()),
            Label::new("setgid", perms.setgid.to_string()),
            Label::new("sticky", perms.sticky.to_string()),
            Label::new("syscall", event.syscall()),
            Label::new("direction", event.direction()),
            Label::new("type_name", event.type_name()),
            // todo: to_owned :(
            Label::new("ips", self.machine_info.string_ips.as_ref().to_owned()),
            Label::new("hostname", self.machine_info.hostname.to_owned()),
            Label::new("machine_id", self.machine_info.id.to_owned()),
        ]
        .into()
    }

    async fn get_file_type(&self, event: &FileAccessEvent) -> Arc<str> {
        self.file_type_by_mode
            .entry(event.file_type_mode())
            .or_insert_with(async {
                match event.file_type() {
                    Ok(ft) => Arc::from(ft.as_ref().to_owned()),
                    Err(types::Error::FileType(err)) => Arc::from(format!("{}", err.number)),
                    _ => unreachable!(),
                }
            })
            .await
            .value()
            .clone()
    }

    async fn get_fs_type(&self, event: &FileAccessEvent) -> Arc<str> {
        self.fs_type_by_magic
            .entry(event.s_magic)
            .or_insert_with(async {
                match event.fs_type() {
                    Ok(fs_type) => Arc::from(fs_type.as_ref().to_owned()),
                    Err(types::Error::FsType(err)) => Arc::from(format!("{}", err.number)),
                    _ => unreachable!(),
                }
            })
            .await
            .value()
            .clone()
    }

    async fn get_device_name(&self, event: &FileAccessEvent) -> Arc<str> {
        self.device_name_by_dev
            .entry(event.dev)
            .or_insert_with(async {
                match event.dev_name().await {
                    Ok(name) => Arc::from(name),
                    Err(_err) => Arc::from(format!("{}:{}", event.major(), event.minor())),
                }
            })
            .await
            .value()
            .clone()
    }

    async fn get_cmd(&self, event: &FileAccessEvent) -> Arc<str> {
        self.cmd_name_by_tgid
            .entry(event.tgid)
            .or_insert_with(async {
                match event.cmdline().await {
                    Ok(cmd) => Arc::from(cmd.name()),
                    Err(_err) => Arc::from(event.comm()),
                }
            })
            .await
            .value()
            .clone()
    }
}
