use crate::process::event_ext::EventExt;
use crate::types;
use fetra_common::FileAccessEvent;
use moka::future::Cache;
use std::sync::Arc;
use std::time::Duration;

pub struct Aggregator {
    cmd_name_by_tgid: Cache<u32, Arc<str>>,
    device_name_by_dev: Cache<u32, Arc<str>>,
    fs_type_by_magic: Cache<u64, Arc<str>>,
}

impl Aggregator {
    pub fn new() -> Self {
        Self {
            cmd_name_by_tgid: Cache::builder()
                .max_capacity(10000)
                .time_to_idle(Duration::from_secs(5))
                .time_to_live(Duration::from_secs(10))
                .build(),
            device_name_by_dev: Cache::builder()
                .max_capacity(10000)
                .time_to_idle(Duration::from_secs(5))
                .time_to_live(Duration::from_secs(10))
                .build(),
            
            fs_type_by_magic: Cache::builder()
                .max_capacity(10000)
                .time_to_idle(Duration::from_secs(5))
                .time_to_live(Duration::from_secs(10))
                .build(),
        }
    }
    pub async fn process_event(&self, event: &FileAccessEvent) -> Result<(), types::Error> {
        let full_name = self.get_full_name(event).await;
        let dev_name = self.get_device_name(event).await;
        let fs_type = event.fs_type()?;
        let file_type = event.file_type()?;
        let perms = event.perms();
        println!("Fs: {fs_type:?}, dev name: {dev_name}, file_type: {file_type:?} {full_name}");
        
        metrics::counter!("io_per_file", "path" => event.path().to_string());

        // let full_name = self.get_full_name(event.tgid, comm);

        // println!("{}", full_name);

        Ok(())
    }
    
    async fn get_labels(&self, event: &FileAccessEvent) -> Vec<metrics::Label> {
        let full_name = self.get_full_name(event).await;
        let dev_name = self.get_device_name(event).await;
        let fs_type = self.get_fs_type(event).await;
        
       
        
        todo!()
    }
    
    
    async fn get_fs_type(&self, event: &FileAccessEvent) -> Arc<str> {
        self.fs_type_by_magic.entry(event.s_magic).or_insert_with(async {
            match event.fs_type() {
                Ok(fs_type) => Arc::from(fs_type.as_ref().to_owned()),
                Err(types::Error::FsType(err)) => {
                    Arc::from(format!("{}", err.number))
                }
                _ => unreachable!(),
            }    
        }).await.value().clone()
    }

    async fn get_device_name(&self, event: &FileAccessEvent) -> Arc<str> {
        self
            .device_name_by_dev
            .entry(event.dev)
            .or_insert_with(async {
                match event.dev_name().await {
                    Ok(name) => Arc::from(name),
                    Err(_err) => Arc::from(format!("{}:{}", event.major(), event.minor())),
                }
            })
            .await
            .value().clone()
    }

    async fn get_full_name(&self, event: &FileAccessEvent) -> Arc<str> {
        self
            .cmd_name_by_tgid
            .entry(event.tgid)
            .or_insert_with(async {
                match event.cmdline().await {
                    Ok(cmd) => Arc::from(cmd.name()),
                    Err(_err) => Arc::from(event.comm()),
                }
            })
            .await
            .value().clone()
    }
}
