use anyhow::{anyhow, Context};
use aya::{programs, Ebpf};
use fmt::Debug;
use std::fmt;

pub trait EbpfExt {
    fn load_program<'a, T>(&'a mut self, name: &str) -> anyhow::Result<&'a mut T>
    where
        &'a mut T: TryFrom<&'a mut programs::Program>,
        <&'a mut T as TryFrom<&'a mut programs::Program>>::Error: Debug;
}

impl EbpfExt for Ebpf {
    fn load_program<'a, T>(&'a mut self, name: &str) -> anyhow::Result<&'a mut T>
    where
        &'a mut T: TryFrom<&'a mut programs::Program>,
        <&'a mut T as TryFrom<&'a mut programs::Program>>::Error: Debug,
    {
        let program = self
            .program_mut(&name)
            .with_context(|| format!("Failed to attach program '{name}'"))?;

        let program: &mut T = program.try_into().map_err(
            |err: <&'a mut T as TryFrom<&'a mut programs::Program>>::Error| {
                anyhow!("Can't convert the program to the type {err:?}")
            },
        )?;

        Ok(program)
    }
}
