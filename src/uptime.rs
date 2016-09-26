/// Functions related to tcp secret reading and updating
use std::io;
use std::io::{Read,Write};
use std::time::Duration;
use std::net::{UdpSocket,TcpListener};
use std::net::{Ipv4Addr,SocketAddr};
use ::util;

#[derive(Debug,Eq,PartialEq)]
pub enum Protocol {
    Tcp,
    Udp,
}

pub trait UptimeReader: Send {
    /// returns contents of /proc/tcp_secrets file
    fn read(&self) -> io::Result<Vec<u8>>;
}

pub struct LocalReader;

impl UptimeReader for LocalReader {
    fn read(&self) -> io::Result<Vec<u8>> {
        use std::fs::File;
        use std::io::prelude::*;
        let mut file = try!(File::open("/proc/beget_uptime")
                        .or(File::open("/proc/tcp_secrets")));
        let mut buf = vec![];
        try!(file.read_to_end(&mut buf));
        Ok(buf)
    }
}

/// Receives secrets over udp
pub struct UdpReader {
    addr: SocketAddr,
}

impl UdpReader {
    pub fn new(addr: SocketAddr) -> Self {
        UdpReader {
            addr: addr
        }
    }
}

impl UptimeReader for UdpReader {
    fn read(&self) -> io::Result<Vec<u8>> {
        use std::net::UdpSocket;

        let mut buf = vec![0;1024];
        let socket = try!(UdpSocket::bind("0.0.0.0:0"));
        let timeout = Duration::new(1, 0);
        try!(socket.set_read_timeout(Some(timeout)));
        try!(socket.set_write_timeout(Some(timeout)));
        loop {
            debug!("[uptime] [{}] sending tcp secret request", self.addr);
            socket.send_to(b"YO", self.addr).unwrap();
            if let Ok(..) = socket.recv_from(&mut buf[0..]) {
                debug!("[uptime] [{}] response received", self.addr);
                return Ok(buf);
            }
        }
    }
}

// TODO: parser should probably be split into
// its own function
/// parses tcp_secrets and updates global table
pub fn update(ip: Ipv4Addr, buf: Vec<u8>) {
    use std::io::prelude::*;
    use std::io::BufReader;

    let mut jiffies = 0;
    let mut tcp_cookie_time = 0;
    let mut hz = 300;
    let mut syncookie_secret: [[u32;17];2] = [[0;17];2];

    debug!("[uptime] [{}] Updating secrets", &ip);
    let reader = BufReader::new(&buf[..]);
    for (idx, line) in reader.lines().enumerate() {
        let line = line.unwrap();
        match idx {
            0 => {
                for (idx, word) in line.split(' ').enumerate() {
                    match idx {
                        0 => { jiffies = word.parse::<u64>().unwrap() },
                        1 => { tcp_cookie_time = word.parse::<u32>().unwrap() },
                        2 => { hz = word.parse::<u32>().unwrap() },
                        _ => {},
                    }
                }
            },
            1 => {
                for (idx, word) in line.split('.').enumerate() {
                    if word == "" {
                        continue;
                    }
                    syncookie_secret[0][idx] = u32::from_str_radix(word, 16).unwrap();
                }
            },
            2 => {
                for (idx, word) in line.split('.').enumerate() {
                    if word == "" {
                        continue;
                    }
                    syncookie_secret[1][idx] = u32::from_str_radix(word, 16).unwrap();
                }
            },
            _ => {},
        }
    }
    //println!("jiffies: {}, tcp_cookie_time: {}, syncookie_secret: {:?}", jiffies, tcp_cookie_time, unsafe { syncookie_secret });
    ::RoutingTable::with_host_config_global_mut(ip, |hc| {
        use std::ptr;
        hc.tcp_timestamp = jiffies as u32;
        hc.tcp_cookie_time = tcp_cookie_time as u32;
        hc.hz = hz;
        unsafe {
            ptr::copy_nonoverlapping(syncookie_secret[0].as_ptr(), hc.syncookie_secret[0 as usize].as_mut_ptr(), 17);
            ptr::copy_nonoverlapping(syncookie_secret[1].as_ptr(), hc.syncookie_secret[1 as usize].as_mut_ptr(), 17);
        }
        debug!("[uptime] [{}] updated secrets {}/{}, [{:?}]", &ip, jiffies, tcp_cookie_time, &hc.syncookie_secret[0][0..8]);
    });
}

struct Server<T> {
    sock: T,
    cookies: bool,
}

impl<T> Server<T> {
    fn enable_cookies(&mut self) {
        if !self.cookies {
            match ::util::set_syncookies(2) {
                Ok(_) => {
                    info!("Syncookies enabled");
                    self.cookies = true;
                },
                Err(e) => error!("{}", e),
            }
        }
    }
}

impl Server<TcpListener> {
    pub fn new_tcp(sa: SocketAddr) -> io::Result<Server<TcpListener>> {
        TcpListener::bind(sa).map(move |sock| Server { sock: sock, cookies: false })
    }

    pub fn run(&mut self) -> ! {
        let timeout = Duration::new(1, 0);

        loop {
            let mut buf = [0; 64];
            if let Ok((mut sock, _)) = self.sock.accept() {
                let _ = sock.set_read_timeout(Some(timeout));
                let _ = sock.set_write_timeout(Some(timeout));

                if let Ok(len) = sock.read(&mut buf) {
                    if len < 2 {
                        continue;
                    }
                } else {
                    continue;
                }

                self.enable_cookies();

                match LocalReader.read() {
                    Ok(buf) => {
                        match sock.write(&buf[..]) {
                            Ok(_) => {},
                            Err(e) => error!("Error sending: {}\n", e),
                        }
                    }
                    Err(e) => error!("Error reading /proc/tcp_secrets: {}", e),
                }
            }
        }
    }

}

impl Server<UdpSocket> {
    pub fn new_udp(sa: SocketAddr) -> io::Result<Server<UdpSocket>> {
        UdpSocket::bind(sa).map(move |sock| Server { sock: sock, cookies: false })
    }

    pub fn run(&mut self) -> ! {
        let timeout = Duration::new(1, 0);

        self.sock.set_read_timeout(Some(timeout)).expect("Cannot set read timeout");
        self.sock.set_write_timeout(Some(timeout)).expect("Cannot set write timeout");

        loop {
            let mut buf = [0; 64];
            if let Ok((len,addr)) = self.sock.recv_from(&mut buf[0..]) {
                if len < 2 {
                    continue;
                }

                self.enable_cookies();

                match LocalReader.read() {
                    Ok(buf) => {
                        match self.sock.send_to(&buf[..], addr) {
                            Ok(_) => {},
                            Err(e) => error!("Error sending: {}\n", e),
                        }
                    }
                    Err(e) => error!("Error reading /proc/tcp_secrets: {}", e),
                }
            }
        }
    }
}

/// main function in "server" mode
pub fn run_server(addr: &str) -> ! {
    use ::chan_signal::Signal;
    use std::thread;

    info!("Listening on {}", addr);
    let (proto, addr) = util::parse_addr(addr).expect("Can't parse address");

    let signal = ::chan_signal::notify(&[Signal::INT, Signal::TERM]);
    thread::spawn(move || loop {
        ::util::set_thread_name("syncookied/sig");
        match signal.recv().unwrap() {
            Signal::INT | Signal::TERM => {
                use std::process;
                match ::util::set_syncookies(1) {
                    Ok(_) => info!("Syncookies if needed"),
                    Err(e) => error!("{}", e),
                };
                info!("SIGINT received, exiting");
                process::exit(0);
            },
            _ => {},
        }
    });

    match proto {
        Protocol::Tcp => Server::new_tcp(addr).unwrap().run(),
        Protocol::Udp => Server::new_udp(addr).unwrap().run(),
    }
}
