use std::env;

use sign_cms_lib::get_sign;

// cargo run --example sign_check
fn main() {
    let dir = "./files/app-release.apk".to_string();
    let current_dir = env::current_dir().unwrap();
    println!("The current directory is {}", current_dir.display());
    let rst = get_sign(dir.to_string());
    match rst {
        Ok(s) => println!("ok: {}", s),
        Err(e) => println!("err: {}", e)
    }
}