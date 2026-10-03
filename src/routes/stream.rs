use std::io::{self, Read};
use std::sync::Arc;

use crossbeam_channel::Receiver;
use tiny_http::{Header, Request, Response};

use crate::broadcaster::Broadcaster;

pub fn handle(request: Request, broadcaster: Arc<Broadcaster>) -> anyhow::Result<()> {
    let rx = broadcaster.subscribe();

    let reader = SseReader {
        rx,
        current: Vec::new(),
        pos: 0,
    };

    let headers = vec![
        Header::from_bytes("Content-Type", "text/event-stream").unwrap(),
        Header::from_bytes("Cache-Control", "no-cache").unwrap(),
        Header::from_bytes("X-Accel-Buffering", "no").unwrap(),
        Header::from_bytes("Access-Control-Allow-Origin", "*").unwrap(),
    ];

    let response = Response::new(tiny_http::StatusCode(200), headers, reader, None, None);

    request.respond(response)?;
    Ok(())
}

struct SseReader {
    rx: Receiver<Vec<u8>>,
    current: Vec<u8>,
    pos: usize,
}

impl Read for SseReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.current.len() {
            match self.rx.recv() {
                Ok(data) => {
                    self.current = data;
                    self.pos = 0;
                }
                Err(_) => return Ok(0),
            }
        }
        let n = std::cmp::min(buf.len(), self.current.len() - self.pos);
        buf[..n].copy_from_slice(&self.current[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}
