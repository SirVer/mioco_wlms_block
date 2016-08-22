const DEFAULT_PORT: u16 = 7395;

extern crate byteorder;
extern crate env_logger;
#[macro_use] extern crate mioco;
extern crate wlms;

use byteorder::{BigEndian, ByteOrder};
use mioco::tcp::{TcpListener, TcpStream};
use std::borrow::Cow;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::ops::Deref;
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use wlms::errors::*;
use wlms::protocol::{PacketParser, Packet};

fn handle_packet(packet: Packet, server: &Arc<RwLock<Server>>, tx: &ClientChannelSender) {
    println!("#sirver packet: {:#?}", packet);
    match packet {
        Packet::Login(data) => {
            println!("#sirver ALIVE {}:{}", file!(), line!());
            let mut s = server.write().unwrap();
            s.clients.push(Client {
                name: data.client_name.clone(),
                build_id: data.build_id,
            });
            tx.send(vec!["LOGIN".into(), data.client_name.into(), "UNREGISTERED".into()]).unwrap();
            println!("#sirver ALIVE {}:{}", file!(), line!());
        },
        Packet::Clients => {
            println!("#sirver ALIVE {}:{}", file!(), line!());
            let s = server.read().unwrap();
            let mut reply: Vec<Cow<str>> = vec!["CLIENTS".into()];
            reply.push(s.clients.len().to_string().into());
            for client in &s.clients {
                reply.push(client.name.clone().into());
                reply.push(client.build_id.clone().into());
                reply.push("".into()); // Game the player is in.
                reply.push("UNREGISTERED".into());
                reply.push("".into()); // Points
            }
            tx.send(reply).unwrap();
            println!("#sirver ALIVE {}:{}", file!(), line!());
        },
        Packet::Games => {
            // TODO(sirver): Implement this properly.
            println!("#sirver ALIVE {}:{}", file!(), line!());
            tx.send(vec!["GAMES".into(), "0".into()]).unwrap();
            println!("#sirver ALIVE {}:{}", file!(), line!());
        }
    }
}

struct Client  {
    name: String,
    build_id: String,
}

fn send_packet<T: Write, Str: Deref<Target=str>>(writer: &mut T, data: &[Str]) -> Result<()> {
    let mut reply = Vec::new();
    reply.push(0);
    reply.push(0);
    for entry in data {
        reply.extend_from_slice(entry.as_bytes());
        reply.push(0);
    }
    let size = reply.len() as u16;
    BigEndian::write_u16(&mut reply[..2], size);
    try!(writer.write_all(&reply));
    Ok(())
}

type ClientChannelSender = mioco::sync::mpsc::SyncSender<Vec<Cow<'static, str>>>;

impl Client {
    fn handle_connection<T: Read + Write + mioco::Evented + Send + 'static>(mut conn: T, server: Arc<RwLock<Server>>) {
        mioco::spawn(move || -> Result<()> {
            let (tx, rx) = mioco::sync::mpsc::sync_channel(5);
            let mut packet_parser = PacketParser::new();

            loop {
                println!("Before select!");
                select!(
                    r:conn => {
                        while let Some(packet) = try!(packet_parser.read_packet(&mut conn)) {
                            println!("#sirver DATA from client");
                            handle_packet(packet, &server, &tx);
                            println!("#sirver done.");
                        }
                    },
                    r:rx => {
                        println!("#sirver DATA from channel");
                        use std::sync::mpsc::TryRecvError::*;
                        let data = match rx.try_recv() {
                            Ok(data) => try!(send_packet(&mut conn, data.as_slice())),
                            Err(Empty) => (),
                            Err(Disconnected) => return Err(ErrorKind::ClientHangup.into()),
                        };
                    },
                );
            }
            Ok(())
        });
    }
}

struct Server {
    clients: Vec<Client>,
}

impl Server {
    fn new() -> Self {
        Server {
            clients: Vec::new(),
        }
    }
}

fn main() {
    mioco::start(|| -> Result<()> {
        let addr: SocketAddr = FromStr::from_str(&format!("0.0.0.0:{}", DEFAULT_PORT)).unwrap();

        let listener = try!(TcpListener::bind(&addr));
        let mut server = Arc::new(RwLock::new(Server::new()));
        println!("Starting tcp echo server on {:?}", try!(listener.local_addr()));
        loop {
            let mut conn = try!(listener.accept());
            // conn.set_read_timeout(Duration::from_secs(0));

            Client::handle_connection(conn, server.clone());
        }
    }).unwrap().unwrap();
}

