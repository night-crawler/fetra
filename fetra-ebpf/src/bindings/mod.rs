#[allow(clippy::all, unnecessary_transmutes)]
mod tmp {
    include!("./pageflags.rs");
    include!("./common.rs");
}

pub use tmp::*;
