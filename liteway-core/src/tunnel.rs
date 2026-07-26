use std::io::{self, Read, Write};
use tun::AbstractDevice;

pub struct TunDevice {
    dev: tun::Device,
}

pub struct TunReader {
    reader: tun::Reader,
}

pub struct TunWriter {
    writer: tun::Writer,
}

impl TunDevice {
    pub fn new(name: &str, mtu: u16) -> io::Result<Self> {
        let mut cfg = tun::Configuration::default();
        cfg.tun_name(name).mtu(mtu).up();

        let dev = tun::create(&cfg).map_err(io::Error::other)?;

        Ok(TunDevice { dev })
    }

    pub fn set_nonblock(&self) -> io::Result<()> {
        #[cfg(unix)]
        self.dev.set_nonblock()?;
        Ok(())
    }

    pub fn set_ip(&mut self, addr: &str) -> io::Result<()> {
        let name = self.dev.tun_name().map_err(io::Error::other)?;
        liteway_net::set_interface_ip(&name, addr)
    }

    pub fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.dev.recv(buf)
    }

    pub fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.dev.send(buf)
    }

    pub fn name(&self) -> String {
        self.dev.tun_name().unwrap_or_default()
    }

    pub fn split(self) -> (TunReader, TunWriter) {
        let (reader, writer) = self.dev.split();
        (TunReader { reader }, TunWriter { writer })
    }
}

impl TunReader {
    pub fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.reader.read(buf)
    }
}

impl TunWriter {
    pub fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.writer.write(buf)
    }

    pub fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

unsafe impl Send for TunDevice {}
unsafe impl Send for TunReader {}
unsafe impl Send for TunWriter {}
