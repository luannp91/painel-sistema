use std::sync::{Arc, Mutex};

use tiny_http::{Header, Method, Request, Response, StatusCode};

use crate::sysinfo::processes::ProcessCollector;

/// GET /api/processes
pub fn list(request: Request, collector: Arc<Mutex<ProcessCollector>>) -> anyhow::Result<()> {
    let procs = {
        let mut c = collector.lock().unwrap();
        c.list()
    };

    let body = serde_json::to_vec(&procs)?;
    let header = Header::from_bytes("Content-Type", "application/json; charset=utf-8").unwrap();
    let cors = Header::from_bytes("Access-Control-Allow-Origin", "*").unwrap();
    let cache = Header::from_bytes("Cache-Control", "no-store").unwrap();

    let response = Response::from_data(body)
        .with_header(header)
        .with_header(cors)
        .with_header(cache);

    request.respond(response)?;
    Ok(())
}

/// POST /api/processes/{pid}/kill
pub fn kill(
    request: Request,
    collector: Arc<Mutex<ProcessCollector>>,
    pid: u32,
) -> anyhow::Result<()> {
    if request.method() != &Method::Post {
        let body = r#"{"error":"method_not_allowed","message":"Use POST para matar processos"}"#;
        let header = Header::from_bytes("Content-Type", "application/json").unwrap();
        let allow = Header::from_bytes("Allow", "POST").unwrap();
        let response = Response::from_string(body)
            .with_status_code(StatusCode(405))
            .with_header(header)
            .with_header(allow);
        request.respond(response)?;
        return Ok(());
    }

    let result = {
        let mut c = collector.lock().unwrap();
        c.kill(pid)
    };

    match result {
        Ok(name) => {
            let body = format!(
                "{{\"status\":\"ok\",\"pid\":{},\"name\":{}}}",
                pid,
                serde_json::to_string(&name)?
            );
            let header = Header::from_bytes("Content-Type", "application/json").unwrap();
            let response = Response::from_string(body).with_header(header);
            request.respond(response)?;
        }
        Err(msg) => {
            let body = format!(
                "{{\"status\":\"error\",\"pid\":{},\"message\":{}}}",
                pid,
                serde_json::to_string(&msg)?
            );
            let header = Header::from_bytes("Content-Type", "application/json").unwrap();
            let response = Response::from_string(body)
                .with_status_code(StatusCode(400))
                .with_header(header);
            request.respond(response)?;
        }
    }

    Ok(())
}

/// Extrai o PID de paths como /api/processes/1234/kill
pub fn parse_kill_path(path: &str) -> Option<u32> {
    let stripped = path.strip_prefix("/api/processes/")?;
    let pid_str = stripped.strip_suffix("/kill")?;
    pid_str.parse::<u32>().ok()
}
