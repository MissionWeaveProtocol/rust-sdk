//! Strictly validate and canonically encode one frame from a file.

use std::env;
use std::fs;

use missionweaveprotocol::FrameCodec;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::args()
        .nth(1)
        .ok_or("usage: cargo run --example validate_frame -- <frame.json>")?;
    let input = fs::read(path)?;
    let codec = FrameCodec::new()?;
    let frame = codec.decode(&input)?;
    let canonical = codec.encode(&frame)?;
    println!("{}", String::from_utf8(canonical)?);
    Ok(())
}
