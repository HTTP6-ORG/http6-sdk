use std::{env, io::{Read,Write}, os::unix::net::UnixStream, time::Duration};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let a:Vec<String>=env::args().collect();
    if a.len()!=4 || a[2].is_empty() || a[2].len()>48 || !a[2].bytes().all(|b|b.is_ascii_lowercase()||b.is_ascii_digit()||b==b'-') || !["allowed","denied"].contains(&a[3].as_str()) {return Err("usage: client SOCKET OP allowed|denied".into());}
    let amount=if a[3]=="allowed"{"100"}else{"1100"};
    let body=format!(r#"{{"args":{{"network":"regtest","recipient":"merchant-a","satoshis":"{}"}},"audience":"wallet","holdSeconds":4,"op":"{}","resource":"merchant-payment"}}"#,amount,a[2]);
    let mut s=UnixStream::connect(&a[1])?;s.set_read_timeout(Some(Duration::from_secs(15)))?;
    write!(s,"POST /http6/v0/propose HTTP/1.0\r\nHost: agent.local\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",body.len(),body)?;
    let mut raw=String::new();s.read_to_string(&mut raw)?;let (headers,payload)=raw.split_once("\r\n\r\n").ok_or("invalid HTTP response")?;
    let status:u16=headers.split_whitespace().nth(1).ok_or("missing status")?.parse()?;
    println!("{{\"status\":{},\"body\":{}}}",status,payload);Ok(())
}
