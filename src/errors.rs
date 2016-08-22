use std::io;
use std::sync::mpsc;

error_chain! {
    foreign_links {
        io::Error, Io;
    }
    
    errors {
        InvalidPacket(t: String) {
            description("invalid packet")
            display("invalid packet: '{}'", t)
        }
        ClientHangup {
            description("Client hangup.")
            display("Client hangup.")
        }
    }
}

