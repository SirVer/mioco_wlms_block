use byteorder::{BigEndian, ByteOrder};
use bytes::{RingBuf, Buf, MutBuf};
use errors::*;
use mio::TryRead;
use nom::{self, IResult};
use std::io::{Read};
use std::mem;
use std::str;

const MAX_PACKET_SIZE: usize = 8 * 8192;

#[derive(Debug)]
pub enum Packet {
    Login(LoginRequest),
    Clients,
    Games,
}

#[derive(Debug)]
pub struct LoginRequest {
    pub protocol_version: i32,
    pub client_name: String,
    pub build_id: String,
    pub login_to_registered: bool,
    pub password: Option<String>,
}

#[derive(Debug)]
pub struct ClientsRequest {}

named!(login_packet<Packet>, chain!(
    protocol_version: number ~
    client_name: string ~
    build_id: string ~
    login_to_registered: boolean ~
    password: cond!(login_to_registered, string),
    || Packet::Login(
        LoginRequest {
            protocol_version: protocol_version,
            client_name: client_name.into(),
            build_id: build_id.into(),
            login_to_registered: login_to_registered,
            password: password.map(|s| s.into()),
        })
));

named!(clients_packet<Packet>, value!(Packet::Clients));

named!(games_packet<Packet>, value!(Packet::Games));

named!(string<&str>, chain!(
    res: map_res!(take_until!(b"\0"), str::from_utf8) ~
    take!(1),
    || res
));

named!(number<i32>, map_res!(string, str::parse));

fn boolean(input: &[u8]) -> IResult<&[u8], bool>{
    let (remaining, value)  = try_parse!(input, string);
    match value {
        "true" => IResult::Done(remaining, true),
        "false" => IResult::Done(remaining, false),
        // TODO(sirver): Probably we have to keep track of these error codes somehow?
        _ => IResult::Error(nom::Err::Position(nom::ErrorKind::Custom(1), input)),

    }
}

fn packet(input: &[u8]) -> IResult<&[u8], Packet>{
    let (remaining, kind) = try_parse!(input, string);
    match kind {
        "LOGIN" => login_packet(remaining),
        "CLIENTS" => clients_packet(remaining),
        "GAMES" => games_packet(remaining),
        // TODO(sirver): This should never panic.
        other => panic!("Not implemented: {}", other),
    }
}

pub struct PacketParser {
    packet_cutter: PacketCutter,
}

impl PacketParser {
    pub fn new() -> Self {
        PacketParser {
            packet_cutter: PacketCutter::new(),
        }
    }

    pub fn read_packet<T: Read>(&mut self, reader: &mut T) -> Result<Option<Packet>> {
        match try!(self.packet_cutter.read_packet(reader)) {
            None => Ok(None), 
            Some(packet_data) => match packet(&packet_data) {
                IResult::Done(r, packet) => {
                    // NOCOM(#sirver): should be an error check
                    assert_eq!(0, r.len());
                    Ok(Some(packet))
                },
                IResult::Error(err) => Err(ErrorKind::InvalidPacket(err.to_string()).into()),
                IResult::Incomplete(_) => Err(ErrorKind::InvalidPacket("Unexpected End of packet.".into()).into()),
            }
        }
    }
}

/// Reads arbitrary bytes and reassembles full protocol packets.
struct PacketCutter {
    unconsumed: usize,
    // TODO(sirver): Use a bytes::RingBuf.
    buf: Vec<u8>,
}

impl PacketCutter {
   fn new() -> Self {
        PacketCutter {
            unconsumed: 0,
            buf: vec![0u8; MAX_PACKET_SIZE],
        }
    }

    fn read_packet<T: Read>(&mut self, reader: &mut T) -> Result<Option<Vec<u8>>> {
        println!("#sirver ALIVE {}:{}", file!(), line!());
        println!("#sirver self.buf[..self.unconsumed]: {:#?}", self.buf[..self.unconsumed].iter().collect::<Vec<&u8>>());
        self.buf.resize(MAX_PACKET_SIZE, 0u8);

        if let Some(packet_data) = self.try_parse() {
            return Ok(Some(packet_data));
        }
        println!("#sirver ALIVE {}:{}", file!(), line!());
        let size = match reader.read(&mut self.buf[self.unconsumed..]) {
            Ok(size) => size,
            Err(e) => {
                println!("#sirver e: {:#?}", e);
                return Err(e.into());
            },
        };
        println!("#sirver ALIVE {}:{}", file!(), line!());
        self.unconsumed += size;

        println!("#sirver self.buf[..self.unconsumed]: {:#?}", self.buf[..self.unconsumed].iter().collect::<Vec<&u8>>());
        println!("#sirver ALIVE {}:{}", file!(), line!());

        Ok(self.try_parse())
    }

    fn try_parse(&mut self) -> Option<Vec<u8>> {
        if self.unconsumed < 2 {
            return None;
        }
        let packet_len = BigEndian::read_u16(&self.buf[..2]) as usize;
        if self.unconsumed < packet_len {
            return None;
        }
        let mut new_buf = self.buf.split_off(packet_len);
        mem::swap(&mut new_buf, &mut self.buf);

        // Remove the first two items in the new buffer (the length).
        new_buf.drain(..2).count();

        self.unconsumed -= packet_len;

        Some(new_buf)
    }
}

#[cfg(test)]
mod test {
    use super::{string, number, PacketCutter};
    use std::io::Cursor;
    use nom::IResult;

    #[test]
    fn test_string() {
        let input = [48u8, 0u8];
        let rv = string(&input);
        assert_eq!(IResult::Done(&b""[..], "0"), rv);
        
    }

    #[test]
    fn test_number() {
        let input = b"100\x00";
        let rv = number(&input[..]);
        assert_eq!(IResult::Done(&b""[..], 100), rv);
    }

    #[test]
    fn test_packet_cutter_empty_packet() {
        let mut reader = Cursor::new(b"");
        let mut packet_cutter = PacketCutter::new();
        assert_eq!(None, packet_cutter.read_packet(&mut reader).unwrap());
    }

    #[test]
    fn test_packet_cutter_simple_packet() {
        let mut reader = Cursor::new(b"\x00\x07Hello");
        let mut packet_cutter = PacketCutter::new();
        assert_eq!(Some(Vec::from("Hello")), packet_cutter.read_packet(&mut reader).unwrap());
        assert_eq!(None, packet_cutter.read_packet(&mut reader).unwrap());
    }

    #[test]
    fn test_packet_cutter_two_packets() {
        let mut reader = Cursor::new(b"\x00\x07Hello\x00\x07Hello");
        let mut packet_cutter = PacketCutter::new();
        assert_eq!(Some(Vec::from("Hello")), packet_cutter.read_packet(&mut reader).unwrap());
        assert_eq!(Some(Vec::from("Hello")), packet_cutter.read_packet(&mut reader).unwrap());
        assert_eq!(None, packet_cutter.read_packet(&mut reader).unwrap());
    }

    #[test]
    fn test_packet_cutter_partial_packet() {
        let mut reader = Cursor::new(b"\x00\x07He");
        let mut packet_cutter = PacketCutter::new();
        assert_eq!(None, packet_cutter.read_packet(&mut reader).unwrap());
        let mut reader = Cursor::new(b"llo");
        assert_eq!(Some(Vec::from("Hello")), packet_cutter.read_packet(&mut reader).unwrap());
    }
}
