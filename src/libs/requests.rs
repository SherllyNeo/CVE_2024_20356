use regex::Regex;
use reqwest;
use elementtree::Element;
use anyhow::{Error, Result, Context};
use std::collections::HashMap;

pub struct Authenticated {
    cookie: Option<String>,
    sid: Option<String>,
    admin_user: bool
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


pub fn login(target: &str, username: &str, password: &str, proxy: Option<&str>, encrypt: fn(&str,&str,Option<Vec<u8>>) -> Result<String>) -> Result<Authenticated,Error> {
    // fix error handling
    println!("Attemting login as: {username}");
	let enc_password = encrypt(username, password,None)?;
    let enc_password_as_string = &enc_password;
    
    let url = format!("https://{target}/data/login");

    let mut client_builder = reqwest::blocking::Client::builder();

    if let Some(prox) = proxy {
        let proxy_http = reqwest::Proxy::http(prox)?;
        let proxy_https = reqwest::Proxy::https(prox)?;

        client_builder = reqwest::blocking::Client::builder()
            .proxy(proxy_http)
            .proxy(proxy_https);
    }

    let client = client_builder.build()?;

    let payload = HashMap::from([
        ("username",username),
        ("password",&enc_password_as_string)
    ]);

    let client_base = client
          .post(&url)
          .header("Referer",format!("{url}.html"))
          .header("Accept-Encoding","identity")
          .json(&payload);

    let response = client_base.send()?;

    if response.status().is_success() {
        println!("success sending log in request");
    } else if response.status().is_server_error() {
        return Err(Error::msg("server error!"));
    } else {
        return Err(Error::msg(format!("Something else happened. Status: {:?}", response.status())));
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

pub fn logout() -> Result<()> {
    todo!();
}

pub fn exec() -> Result<()> {
    todo!();
}


