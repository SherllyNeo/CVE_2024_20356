use regex::Regex;
use reqwest;
use elementtree::Element;
use anyhow::{Error, Result, Context};
use crate::libs::arguments::Actions;
use std::collections::HashMap;
use reqwest::blocking::Client;
use crate::libs::encryption::hash_fnv32;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};

pub struct Authenticated {
    pub cookie: Option<String>,
    pub sid: Option<String>,
    pub admin_user: bool
}

fn extract_session_cookie(full_cookie: &str) -> Result<&str> {
    let re = Regex::new(r"sessionCookie=([a-z0-9]{32});").context("unable to compile regex")?;
    
    let captures = re.captures(&full_cookie)
        .context("Failed to find a match for the session cookie")?;
    
    // Extract the first capture group
    let cookie_value = captures.get(1)
        .context("Failed to extract the session cookie value")?
        .as_str();
    Ok(cookie_value)
}

fn build_client(proxy: Option<&str>) -> Result<Client> {
    let mut client_builder = reqwest::blocking::Client::builder();

    if let Some(prox) = proxy {
        let proxy_http = reqwest::Proxy::http(prox)?;
        let proxy_https = reqwest::Proxy::https(prox)?;

        client_builder = reqwest::blocking::Client::builder()
            .proxy(proxy_http)
            .proxy(proxy_https);
    }

    let client = client_builder
        .danger_accept_invalid_certs(true)
        .build()?;

    Ok(client)
}

pub fn login(target: &str, username: &str, password: &str, proxy: Option<&str>, encrypt: fn(&str,&str,Option<Vec<u8>>) -> Result<String>) -> Result<Authenticated,Error> {
    // fix error handling
    println!("Attemting login as: {username}");
	let enc_password = encrypt(username, password,None)?;
    let enc_password_as_string = &enc_password;
    
    let url = format!("https://{target}/data/login");


    let payload = HashMap::from([
        ("username",username),
        ("password",&enc_password_as_string)
    ]);

    let client = build_client(proxy)?;

    let client_base = client
          .post(&url)
          .header("Referer",format!("{url}.html"))
          .header("Accept-Encoding","identity")
          .json(&payload);

    let response = client_base.send()?;

    if response.status().is_success() {
        println!("success sending login request");
    } else if response.status().is_server_error() {
        return Err(Error::msg("server error!"));
    } else {
        return Err(Error::msg(format!("Something bad happened. Status: {:?}", response.status())));
    }

    // This needs lots of testing
    let cookie_headers = response
        .headers().clone()
        .get("Set-Cookie")
        .ok_or_else(|| Error::msg("Unable to find Set-Cookie in response headers"))?
        .to_str()?
        .to_string();


    let response_raw = response.bytes()?.to_vec();


    let root = Element::from_reader(response_raw.as_slice())?;

    let auth_result = root.find("authResult")
        .ok_or_else(|| Error::msg("Unable to find Set-Cookie in response headers"))?
        .text();

    if auth_result != "0" {
        return Err(Error::msg(format!("authResult is {auth_result} not 0")));
    }

    let admin_user_text = root.find("adminUser")
        .ok_or_else(|| Error::msg("Unable to find adminUser element"))?
        .text();

    let admin_user = admin_user_text == "1";


    let sid = root.find("sidValue")
        .ok_or_else(|| Error::msg("Unable to find sidValue element"))?
        .text();

    let cookie_value = extract_session_cookie(&cookie_headers)?;
    

    let authenticated = Authenticated {
        admin_user : admin_user,
        sid : Some(sid.to_owned()),
        cookie: Some(cookie_value.to_owned())
    };

    Ok(authenticated)
          
}

pub fn logout(target: &str, sid_value: &str,proxy: Option<&str>) -> Result<()> {
    println!("Logging out: {}XXXXXXXXXXXXXXXXXXXXXXXX",sid_value.get(0..8).context("sid value should be at least 8 characters long")?);
    let url = format!("https://{target}/data/logout");
    let payload = HashMap::from([
        ("sessionID",sid_value)
    ]);
    let client = build_client(proxy)?;

    let client_base = client
        .post(&url)
        .header("Referer",format!("{url}.html"))
        .header("Accept-Encoding","identity")
        .json(&payload);

    let response = client_base.send()?;

    if response.status().is_success() {
        println!("success sending logout request");
    } else if response.status().is_server_error() {
        return Err(Error::msg("server error!"));
    } else {
        return Err(Error::msg(format!("Something bad happened. Status: {:?}", response.status())));
    }

    todo!();
}

fn query(target: &str, cookie: &str, sid: &str, input_cmd: &str, proxy: Option<&str>) -> Result<Element>{
    let url = format!("https://{target}");

    let cmd = utf8_percent_encode(input_cmd, NON_ALPHANUMERIC).to_string();

    let payload = HashMap::from([
        ("sessionID",sid),
        ("queryString",&cmd)
    ]);

    let client = build_client(proxy)?;

    let client_base = client
          .post(&url)
          .header("Referer",format!("https://{target}/index.html"))
          .header("Cookie",format!("sessionCookie={cookie}"))
          .header("Accept-Encoding","identity")
          .header("Cspg_var",hash_fnv32(sid,input_cmd).context("unable to hash sid and input")?)
          .json(&payload);

    let response = client_base.send()?;

    if response.status().is_success() {
        println!("success sending login request");
    } else if response.status().is_server_error() {
        return Err(Error::msg("server error!"));
    } else {
        return Err(Error::msg(format!("Something bad happened. Status: {:?}", response.status())));
    }


    let response_raw = response.bytes()?.to_vec();


    let root = Element::from_reader(response_raw.as_slice())?;
    Ok(root)
}


fn exec() -> Result<()> {
    todo!();
}

pub fn get_host_info() -> Result<()>{
    todo!();
}

pub fn run_test() -> Result<()>{
    todo!();
}

pub fn run_command() -> Result<()>{
    todo!();
}

pub fn run_shell() -> Result<()>{
    todo!();
}

pub fn run_dance() -> Result<()>{
    todo!();
}

pub fn handle_action(action: &Actions) -> Result<()> {
    match action {
        Actions::Test => run_test()?,
        Actions::Cmd => run_command()?,
        Actions::Shell => run_shell()?,
        Actions::Dance => run_dance()?
    }
    Ok(())
}



