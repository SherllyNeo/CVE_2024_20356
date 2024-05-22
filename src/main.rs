mod libs;
use libs::arguments::Args;
use libs::arguments::Actions;
use libs::actions::{login,logout};
use libs::encryption::encrypt;
use clap::Parser;
use std::process::exit;





fn headers() {
    println!(" \
   _____ _____  _____  _____                    \n\
  / ____|_   _|/ ____|/ ____|                   \n\
 | |      | | | (___ | |     _____      ___ __   \n\
 | |      | |  \\___ \\| |    / _ \\ \\ /\\ / / '_ \\  \n\
 | |____ _| |_ ____) | |___| (_) \\ V  V /| | | | \n\
  \\_____|_____|_____/ \\_____ \\___/ \\_/\\_/ |_| |_| \n\
		\n");
	println!("~ Because every vulnerability needs a cool tool");
	println!("~ AThacker @ LRQA Nettitude | v1.0\nOxidized by SherllyNeo");
	println!("This proof-of-concept is for demonstration purposes and should not be used for illegal activities.\nLRQA Nettitude are not responsible for any damage caused by the use or misuse of this code.");

}


fn main() {
    let args = Args::parse();
    let proxy = None;
    headers();

    let authenticated = match login(&args.hostname,&args.username,&args.password,proxy,encrypt) {
        Ok(auth) => {   
            println!("[+] Logged in");
            auth
        }
        Err(err) => {
            println!("[-] unable to log in due to error: {err}");
            exit(1);
        }
    };

    match args.action {
        Actions::Test => println!("test"),
        Actions::Cmd => println!("cmd {:?}",args.cmd),
        Actions::Shell => println!("Shell"),
        Actions::Dance => println!("Dance"),
    }

    match logout(&args.hostname,&authenticated.sid.expect("shoul have sid value"),proxy) {
        Ok(_) => {
            println!("[+] Logged out :)");
        }
        Err(err) => {
            println!("[-] unable to logout in due to error: {err}");
            exit(1);
        }
    };




}

