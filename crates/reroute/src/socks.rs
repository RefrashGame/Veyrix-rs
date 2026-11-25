//! Клиент SOCKS5 (RFC 1928): CONNECT к IPv4-адресу, без пароля или с логином и паролем (RFC 1929).
//! Так подключаются и к своему прокси, и к Cloudflare WARP в режиме прокси (127.0.0.1:40000).

use std::io::{self, Read, Write};
use std::net::{SocketAddr, SocketAddrV4, TcpStream};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proxy {
    pub addr: SocketAddr,
    pub login: Option<(String, String)>,
}

impl Proxy {
    /// «host:port», «socks5://host:port» или «socks5://логин:пароль@host:port»; host — IP-адрес.
    pub fn parse(text: &str) -> Result<Self, String> {
        let rest = text.trim().strip_prefix("socks5://").unwrap_or(text.trim());
        let (login, hostport) = match rest.rsplit_once('@') {
            Some((cred, hp)) => {
                let (user, pass) = cred.split_once(':').ok_or("логин и пароль пишутся как логин:пароль@адрес")?;
                (Some((user.to_string(), pass.to_string())), hp)
            }
            None => (None, rest),
        };
        let addr = hostport
            .parse::<SocketAddr>()
            .map_err(|_| format!("«{hostport}»: нужен IP-адрес и порт, например 127.0.0.1:1080"))?;
        Ok(Self { addr, login })
    }

    /// Соединение с `target` через прокси.
    pub fn connect(&self, target: SocketAddrV4, timeout: Duration) -> io::Result<TcpStream> {
        let mut s = TcpStream::connect_timeout(&self.addr, timeout)?;
        s.set_read_timeout(Some(timeout))?;
        s.set_nodelay(true)?;
        handshake(&mut s, self.login.as_ref(), target)?;
        s.set_read_timeout(None)?;
        Ok(s)
    }
}

fn fail(text: &str) -> io::Error {
    io::Error::other(text.to_string())
}

fn handshake(s: &mut (impl Read + Write), login: Option<&(String, String)>, target: SocketAddrV4) -> io::Result<()> {
    let method = if login.is_some() { 2 } else { 0 };
    s.write_all(&[5, 1, method])?;
    let mut reply = [0u8; 2];
    s.read_exact(&mut reply)?;
    if reply[0] != 5 || reply[1] != method {
        return Err(fail("прокси не принял способ входа SOCKS5"));
    }
    if let Some((user, pass)) = login {
        let mut auth = vec![1, user.len() as u8];
        auth.extend(user.as_bytes());
        auth.push(pass.len() as u8);
        auth.extend(pass.as_bytes());
        s.write_all(&auth)?;
        s.read_exact(&mut reply)?;
        if reply[1] != 0 {
            return Err(fail("прокси не принял логин и пароль"));
        }
    }
    let mut req = vec![5, 1, 0, 1];
    req.extend(target.ip().octets());
    req.extend(target.port().to_be_bytes());
    s.write_all(&req)?;
    let mut head = [0u8; 4];
    s.read_exact(&mut head)?;
    if head[1] != 0 {
        return Err(fail(&format!("прокси не соединился с {target} (код SOCKS5 {})", head[1])));
    }
    // Адрес, привязанный прокси, — пропускаем.
    let skip = match head[3] {
        1 => 4 + 2,
        4 => 16 + 2,
        3 => {
            let mut len = [0u8; 1];
            s.read_exact(&mut len)?;
            usize::from(len[0]) + 2
        }
        _ => return Err(fail("непонятный ответ SOCKS5")),
    };
    let mut rest = vec![0u8; skip];
    s.read_exact(&mut rest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// Поток-заглушка: читает заготовленный ответ, запоминает записанное.
    struct Mock {
        input: io::Cursor<Vec<u8>>,
        output: Vec<u8>,
    }
    impl Read for Mock {
        fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
            self.input.read(b)
        }
    }
    impl Write for Mock {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.output.extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    const TARGET: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(162, 159, 134, 232), 443);

    #[test]
    fn connect_without_password() {
        let mut m = Mock { input: io::Cursor::new(vec![5, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0]), output: vec![] };
        handshake(&mut m, None, TARGET).unwrap();
        assert_eq!(m.output, vec![5, 1, 0, 5, 1, 0, 1, 162, 159, 134, 232, 1, 187]);
    }

    #[test]
    fn connect_with_password_and_refusal() {
        let login = ("u".to_string(), "p".to_string());
        let mut m = Mock { input: io::Cursor::new(vec![5, 2, 1, 0, 5, 5, 0, 1]), output: vec![] };
        let err = handshake(&mut m, Some(&login), TARGET).unwrap_err();
        assert!(err.to_string().contains("код SOCKS5 5"));
        assert_eq!(&m.output[..8], &[5, 1, 2, 1, 1, b'u', 1, b'p']);
    }

    #[test]
    fn parse_addresses() {
        assert_eq!(Proxy::parse("127.0.0.1:40000").unwrap().addr, "127.0.0.1:40000".parse().unwrap());
        let p = Proxy::parse("socks5://me:secret@10.0.0.2:1080").unwrap();
        assert_eq!(p.login, Some(("me".into(), "secret".into())));
        assert!(Proxy::parse("example.com:1080").is_err());
    }
}
