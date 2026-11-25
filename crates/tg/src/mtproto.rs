//! MTProto-прокси с secret (obfuscated2): клиент шифрует init ключом SHA256(prekey + secret), прокси читает из него
//! DC и транспорт, строит свой init к Telegram и перешифровывает поток в обе стороны.

use std::net::Ipv4Addr;

use crate::crypto::{AesCtr, random, sha256};

pub const INIT_LEN: usize = 64;
pub const ABRIDGED: u32 = 0xEFEF_EFEF;
pub const INTERMEDIATE: u32 = 0xEEEE_EEEE;
pub const PADDED_INTERMEDIATE: u32 = 0xDDDD_DDDD;

/// Адреса DC для прямого TCP (DC_DEFAULT_IPS из tg-ws-proxy).
pub fn dc_address(dc: i32) -> Option<Ipv4Addr> {
    Some(match dc {
        1 => Ipv4Addr::new(149, 154, 175, 50),
        2 => Ipv4Addr::new(149, 154, 167, 51),
        3 => Ipv4Addr::new(149, 154, 175, 100),
        4 => Ipv4Addr::new(149, 154, 167, 91),
        5 => Ipv4Addr::new(149, 154, 171, 5),
        203 => Ipv4Addr::new(91, 105, 192, 100),
        _ => return None,
    })
}

/// 16 случайных байт в hex — secret прокси; в ссылку Telegram идёт с префиксом «dd».
pub fn new_secret() -> String {
    let mut b = [0u8; 16];
    random(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn parse_secret(hex: &str) -> Option<[u8; 16]> {
    if hex.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(hex.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// Ссылка, по которой Telegram Desktop сам предлагает подключиться к прокси.
pub fn telegram_link(port: u16, secret_hex: &str) -> String {
    format!("tg://proxy?server=127.0.0.1&port={port}&secret=dd{secret_hex}")
}

/// Расшифрованный init клиента: DC, медиа, транспорт и 48 байт ключа+IV.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handshake {
    pub dc: i32,
    pub media: bool,
    pub protocol: u32,
    pub prekey_iv: [u8; 48],
}

fn key_iv(bytes: &[u8]) -> ([u8; 32], [u8; 16]) {
    (bytes[..32].try_into().expect("32"), bytes[32..48].try_into().expect("16"))
}

pub fn parse_handshake(init: &[u8; INIT_LEN], secret: &[u8; 16]) -> Option<Handshake> {
    let prekey_iv: [u8; 48] = init[8..56].try_into().ok()?;
    let (prekey, iv) = key_iv(&prekey_iv);
    let mut plain = *init;
    AesCtr::new(&sha256(&[&prekey, secret]), &iv).apply(&mut plain);
    let protocol = u32::from_le_bytes(plain[56..60].try_into().ok()?);
    if ![ABRIDGED, INTERMEDIATE, PADDED_INTERMEDIATE].contains(&protocol) {
        return None;
    }
    let index = i16::from_le_bytes([plain[60], plain[61]]);
    let dc = i32::from(index).abs();
    ((1..=5).contains(&dc) || dc == 203).then_some(Handshake { dc, media: index < 0, protocol, prekey_iv })
}

/// Свой init к Telegram: случайные байты (не похожие на другие транспорты) + зашифрованные транспорт и DC.
pub fn relay_init(protocol: u32, dc: i32, media: bool) -> [u8; INIT_LEN] {
    let mut init = [0u8; INIT_LEN];
    loop {
        random(&mut init);
        let first = u32::from_le_bytes(init[..4].try_into().expect("4"));
        let second = u32::from_le_bytes(init[4..8].try_into().expect("4"));
        let bad_first = [0x4441_4548, 0x5453_4F50, 0x2054_4547, 0xEEEE_EEEE, 0xDDDD_DDDD, 0x0201_0316, 0x4954_504F];
        if init[0] != 0xEF && !bad_first.contains(&first) && second != 0 {
            break;
        }
    }
    let mut tail = [0u8; 8];
    tail[..4].copy_from_slice(&protocol.to_le_bytes());
    tail[4..6].copy_from_slice(&(if media { -dc } else { dc } as i16).to_le_bytes());
    random(&mut tail[6..]);

    let (key, iv) = key_iv(&init[8..56]);
    let mut encrypted = init;
    AesCtr::new(&key, &iv).apply(&mut encrypted);
    for i in 0..8 {
        init[56 + i] ^= tail[i] ^ encrypted[56 + i];
    }
    init
}

/// WebSocket-входы веб-версии Telegram; для медиа сначала «-1». DC 203 обслуживает DC2.
pub fn ws_domains(dc: i32, media: bool) -> [String; 2] {
    let dc = if dc == 203 { 2 } else { dc };
    let (a, b) = (format!("kws{dc}.web.telegram.org"), format!("kws{dc}-1.web.telegram.org"));
    if media { [b, a] } else { [a, b] }
}

/// Четыре шифра: от клиента, к клиенту, к Telegram, от Telegram. Обратное направление — перевёрнутые 48 байт init.
pub struct Ciphers {
    pub from_client: AesCtr,
    pub to_client: AesCtr,
    pub to_telegram: AesCtr,
    pub from_telegram: AesCtr,
}

impl Ciphers {
    pub fn new(client: &Handshake, secret: &[u8; 16], relay: &[u8; INIT_LEN]) -> Self {
        let fwd = client.prekey_iv;
        let mut rev = fwd;
        rev.reverse();
        let (fk, fiv) = key_iv(&fwd);
        let (rk, riv) = key_iv(&rev);
        let mut from_client = AesCtr::new(&sha256(&[&fk, secret]), &fiv);
        from_client.skip(INIT_LEN); // init клиента уже прочитан

        let relay_fwd: [u8; 48] = relay[8..56].try_into().expect("48");
        let mut relay_rev = relay_fwd;
        relay_rev.reverse();
        let (tk, tiv) = key_iv(&relay_fwd);
        let (bk, biv) = key_iv(&relay_rev);
        let mut to_telegram = AesCtr::new(&tk, &tiv);
        to_telegram.skip(INIT_LEN); // свой init отправлен как есть
        Self {
            from_client,
            to_client: AesCtr::new(&sha256(&[&rk, secret]), &riv),
            to_telegram,
            from_telegram: AesCtr::new(&bk, &biv),
        }
    }
}

/// Делит поток на транспортные пакеты MTProto: ретранслятор Telegram принимает один пакет на кадр WebSocket.
/// Границы ищутся по расшифрованному тексту, режется шифротекст; неполный пакет ждёт следующих данных.
pub struct PacketSplitter {
    protocol: u32,
    cipher: Vec<u8>,
    plain: Vec<u8>,
    disabled: bool,
}

impl PacketSplitter {
    pub fn new(protocol: u32) -> Self {
        Self { protocol, cipher: Vec::new(), plain: Vec::new(), disabled: false }
    }

    pub fn split(&mut self, cipher: &[u8], plain: &[u8]) -> Vec<Vec<u8>> {
        if self.disabled {
            return vec![cipher.to_vec()];
        }
        self.cipher.extend_from_slice(cipher);
        self.plain.extend_from_slice(plain);
        let mut parts = Vec::new();
        let mut offset = 0;
        while offset < self.cipher.len() {
            match self.next_len(offset) {
                None => break, // пакет ещё не пришёл целиком
                Some(0) => {
                    // непонятная разметка — дальше без деления
                    parts.push(self.cipher[offset..].to_vec());
                    offset = self.cipher.len();
                    self.disabled = true;
                }
                Some(len) => {
                    parts.push(self.cipher[offset..offset + len].to_vec());
                    offset += len;
                }
            }
        }
        self.cipher.drain(..offset);
        self.plain.drain(..offset);
        parts
    }

    /// Остаток при закрытии соединения.
    pub fn flush(&mut self) -> Option<Vec<u8>> {
        (!self.cipher.is_empty()).then(|| std::mem::take(&mut self.cipher))
    }

    /// Длина пакета с заголовком; `None` — не хватает данных, `Some(0)` — разметка непонятна.
    fn next_len(&self, offset: usize) -> Option<usize> {
        let p = &self.plain[offset..];
        if self.protocol == ABRIDGED {
            let first = *p.first()?;
            let (header, payload) = if first == 0x7F || first == 0xFF {
                if p.len() < 4 {
                    return None;
                }
                (4, (usize::from(p[1]) | usize::from(p[2]) << 8 | usize::from(p[3]) << 16) * 4)
            } else {
                (1, usize::from(first & 0x7F) * 4)
            };
            if payload == 0 {
                return Some(0);
            }
            return (p.len() >= header + payload).then_some(header + payload);
        }
        if p.len() < 4 {
            return None;
        }
        let len = (u32::from_le_bytes(p[..4].try_into().ok()?) & 0x7FFF_FFFF) as usize;
        if len == 0 {
            return Some(0);
        }
        (p.len() >= 4 + len).then_some(4 + len)
    }
}

/// Сторона клиента (как Telegram Desktop): init и ключи — для самопроверки и тестов.
pub struct Client {
    pub init: [u8; INIT_LEN],
    pub encrypt: AesCtr,
    pub decrypt: AesCtr,
}

impl Client {
    pub fn new(secret: &[u8; 16], protocol: u32, dc_index: i16) -> Self {
        let mut rnd = [0u8; INIT_LEN];
        random(&mut rnd);
        rnd[0] = 0x11; // не 0xEF и не служебные сигнатуры
        let (pk, piv) = key_iv(&rnd[8..56]);
        let mut encrypt = AesCtr::new(&sha256(&[&pk, secret]), &piv);
        let mut encrypted = rnd;
        encrypt.apply(&mut encrypted); // поток шифрования сдвинут на 64 байта init
        let mut tail = [0u8; 8];
        tail[..4].copy_from_slice(&protocol.to_le_bytes());
        tail[4..6].copy_from_slice(&dc_index.to_le_bytes());
        for i in 0..8 {
            rnd[56 + i] ^= tail[i] ^ encrypted[56 + i];
        }
        let mut rev: [u8; 48] = rnd[8..56].try_into().expect("48");
        rev.reverse();
        let (rk, riv) = key_iv(&rev);
        Self { init: rnd, encrypt, decrypt: AesCtr::new(&sha256(&[&rk, secret]), &riv) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: [u8; 16] = [7; 16];

    #[test]
    fn client_init_is_understood_by_proxy() {
        for (dc_index, dc, media) in [(2i16, 2, false), (-4, 4, true), (203, 203, false)] {
            let c = Client::new(&SECRET, INTERMEDIATE, dc_index);
            let hs = parse_handshake(&c.init, &SECRET).expect("рукопожатие");
            assert_eq!((hs.dc, hs.media, hs.protocol), (dc, media, INTERMEDIATE));
        }
        let c = Client::new(&SECRET, ABRIDGED, 2);
        assert!(parse_handshake(&c.init, &[8; 16]).is_none(), "чужой secret");
    }

    #[test]
    fn traffic_survives_reencryption_both_ways() {
        let mut client = Client::new(&SECRET, ABRIDGED, 2);
        let hs = parse_handshake(&client.init, &SECRET).unwrap();
        let relay = relay_init(hs.protocol, hs.dc, hs.media);
        let mut proxy = Ciphers::new(&hs, &SECRET, &relay);

        // Клиент → прокси → «Telegram»: Telegram расшифровывает ключом из relay init.
        let message = b"hello telegram, this is longer than one block".to_vec();
        let mut wire = message.clone();
        client.encrypt.apply(&mut wire);
        proxy.from_client.apply(&mut wire);
        proxy.to_telegram.apply(&mut wire);
        let (tk, tiv) = key_iv(&relay[8..56]);
        let mut telegram_in = AesCtr::new(&tk, &tiv);
        telegram_in.skip(INIT_LEN);
        telegram_in.apply(&mut wire);
        assert_eq!(wire, message);

        // «Telegram» → прокси → клиент.
        let mut rev: [u8; 48] = relay[8..56].try_into().unwrap();
        rev.reverse();
        let (bk, biv) = key_iv(&rev);
        let mut back = b"answer".to_vec();
        AesCtr::new(&bk, &biv).apply(&mut back);
        proxy.from_telegram.apply(&mut back);
        proxy.to_client.apply(&mut back);
        client.decrypt.apply(&mut back);
        assert_eq!(back, b"answer");

        // Init к Telegram сам несёт транспорт и DC.
        let mut check = relay;
        AesCtr::new(&tk, &tiv).apply(&mut check);
        assert_eq!(u32::from_le_bytes(check[56..60].try_into().unwrap()), ABRIDGED);
        assert_eq!(i16::from_le_bytes([check[60], check[61]]), 2);
        assert_ne!(relay[0], 0xEF);
    }

    #[test]
    fn splitter_abridged_and_intermediate() {
        let mut s = PacketSplitter::new(ABRIDGED);
        // Пакеты 1+8 и 4+(1*4)*... : короткий заголовок (2 слова) и длинный 0x7F (1 слово), второй приходит частями.
        let p1 = [vec![2u8], vec![0xAA; 8]].concat();
        let p2 = [vec![0x7F, 1, 0, 0], vec![0xBB; 4]].concat();
        let stream = [p1.clone(), p2.clone()].concat();
        let parts = s.split(&stream[..11], &stream[..11]);
        assert_eq!(parts, vec![p1]);
        assert_eq!(s.split(&stream[11..], &stream[11..]), vec![p2]);
        assert!(s.flush().is_none());

        let mut i = PacketSplitter::new(INTERMEDIATE);
        let pkt = [6u32.to_le_bytes().to_vec(), vec![1, 2, 3, 4, 5, 6]].concat();
        assert_eq!(i.split(&pkt[..5], &pkt[..5]), Vec::<Vec<u8>>::new());
        assert_eq!(i.split(&pkt[5..], &pkt[5..]), vec![pkt.clone()]);

        let mut broken = PacketSplitter::new(INTERMEDIATE);
        assert_eq!(broken.split(&[0, 0, 0, 0, 9], &[0, 0, 0, 0, 9]), vec![vec![0, 0, 0, 0, 9]]);
        assert_eq!(broken.split(&[1, 2], &[1, 2]), vec![vec![1, 2]]); // дальше без деления
    }

    #[test]
    fn secrets_and_links() {
        let s = new_secret();
        assert_eq!(s.len(), 32);
        assert!(parse_secret(&s).is_some());
        assert!(parse_secret("zz").is_none());
        assert_eq!(telegram_link(1443, "ab"), "tg://proxy?server=127.0.0.1&port=1443&secret=ddab");
        assert_eq!(ws_domains(203, true), ["kws2-1.web.telegram.org".to_string(), "kws2.web.telegram.org".to_string()]);
    }
}
