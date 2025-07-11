use crate::bindings::qstr;

pub trait QstrExt {
    fn len(&self) -> u32;
}

impl QstrExt for qstr {
    fn len(&self) -> u32 {
        unsafe { self.__bindgen_anon_1.__bindgen_anon_1.len as u32 }
    }
}
