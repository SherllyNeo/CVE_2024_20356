use clap::Parser;
use serde::Serialize;

#[derive(
    clap::ValueEnum, Clone, Debug, Serialize
)]
#[serde(rename_all = "snake_case")]
pub enum Actions {
    Test,
    Cmd,
    Shell,
    Dance,
}

impl ToString for Actions {
    fn to_string(&self) -> String {
        match self {
            Actions::Test => "test".to_owned(),
            Actions::Cmd => "cmd".to_owned(),
            Actions::Shell => "shell".to_owned(),
            Actions::Dance => "dance".to_owned()
        }
    }
}


#[derive(Parser, Debug)]
#[command(arg_required_else_help(true))]
#[command(version, about, long_about = None)]
pub struct Args {
    /// Target hostname or IP address (format 10.0.0.1 or 10.0.0.2:1337) 
    #[arg(short = 't', long = "host")]
    pub hostname: String,

    /// Username 
    #[arg(short, long, default_value_t = String::from("admin"))]
    pub username: String,
    
    /// Password 
    #[arg(short, long, default_value_t = String::from("cisco"))]
    pub password: String,

    /// Action to perform
    #[arg(short, long, default_value_t = Actions::Test)]
    pub action: Actions,

    /// OS command to run [default: None]
    #[arg(short, long)]
    pub cmd: Option<String>,

    /// Displays more information about cimc
    #[arg(short, long, default_value_t = false)]
    pub verbose: bool

}

