#[macro_use]
extern crate clap;
extern crate libhimitsu;
extern crate rand;
extern crate rpassword;
extern crate serde;
extern crate serde_json;
extern crate serde_yaml;
extern crate toml;

#[cfg(test)]
extern crate tempfile;

use std::fs::File;
use std::io::{self, Read, Write};

use clap::{App, AppSettings, Arg, ArgMatches, SubCommand};
use libhimitsu::Vault;
use rand::{OsRng, Rng};

arg_enum! {
    #[derive(Debug)]
    pub enum Format {
        Json,
        Toml,
        Yaml
    }
}

impl Format {
    fn to_str(&self) -> &'static str {
        match *self {
            Format::Json => "json",
            Format::Toml => "toml",
            Format::Yaml => "yaml",
        }
    }

    fn possible_values() -> &'static [&'static str] {
        &["json", "toml", "yaml"]
    }
}

fn main() {
    let args = make_parser().get_matches();
    let result = run_subcommand(&args);

    std::process::exit(match result {
        Ok(()) => 0,
        Err(e) => {
            println!("Error: {}", e);
            1
        }
    });
}

fn run_subcommand(args: &ArgMatches) -> Result<(), String> {
    match args.subcommand() {
        ("encrypt", Some(args)) => run_encrypt(args),
        ("decrypt", Some(args)) => run_decrypt(args),
        _ => Err("Unknown command or missing options".to_string()),
    }
}

fn run_encrypt(args: &ArgMatches) -> Result<(), String> {
    let input = args.value_of("input").or_else(|| Some("-"));
    let output = args.value_of("output").or_else(|| Some("-"));

    let nonce = args.value_of("nonce");
    let salt = args.value_of("salt");
    let password = args.value_of("password");

    let format = value_t!(args, "format", Format).map_err(|e| e.to_string())?;

    if dash_count(
        [
            input.as_ref(),
            nonce.as_ref(),
            salt.as_ref(),
            password.as_ref(),
        ].into_iter(),
    ) > 1
    {
        Err("Only one input source can be from STDIN")?
    }

    let encrypted = {
        // Read and deserialize the vault.
        let input = input_reader(input.unwrap())?;
        let nonce = match nonce {
            Some(path) => Some(input_reader(path)?),
            None => None,
        };

        let salt = match salt {
            Some(path) => Some(input_reader(path)?),
            None => None,
        };

        let password = match password {
            Some(path) => {
                let reader = input_reader(path)?;
                let buffer = read_to_vec(reader)?;
                String::from_utf8(buffer).map_err(|e| e.to_string())?
            }
            None => {
                let password = rpassword::prompt_password_stdout(
                    "Enter the password to encrypt the vault with: ",
                ).map_err(|e| e.to_string())?;

                let confirmation = rpassword::prompt_password_stdout("Confirm your password: ")
                    .map_err(|e| e.to_string())?;

                if password != confirmation {
                    Err("Passwords entered do not match".to_string())?
                }

                password
            }
        };
        encrypt(password.as_bytes(), format, input, nonce, salt)?
    };

    // Write
    {
        let mut output = output_writer(output.unwrap())?; // safe to unwrap
        let _ = output.write_all(&encrypted).map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn run_decrypt(args: &ArgMatches) -> Result<(), String> {
    let input = args.value_of("input").or_else(|| Some("-"));
    let output = args.value_of("output").or_else(|| Some("-"));

    let password = args.value_of("password");

    let format = value_t!(args, "format", Format).map_err(|e| e.to_string())?;

    if dash_count([input.as_ref(), password.as_ref()].into_iter()) > 1 {
        Err("Only one input source can be from STDIN")?
    }

    let password = match password {
        Some(path) => {
            let reader = input_reader(path)?;
            let buffer = read_to_vec(reader)?;
            String::from_utf8(buffer).map_err(|e| e.to_string())?
        }
        None => rpassword::prompt_password_stdout("Enter the password to decrypt the vault with: ")
            .map_err(|e| e.to_string())?,
    };

    let input = input_reader(input.unwrap())?; // safe to unwrap

    // Read and decrypt the vault. Drop the handler so that we can write back to the same file
    let vault = decrypt(input, password.as_bytes())?;

    // Serialize the vault
    let serialized = serialize_vault(&vault, format)?;

    // Write
    {
        let mut output = output_writer(output.unwrap())?; // safe to unwrap
        let _ = output
            .write_all(serialized.as_bytes())
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Performs the encryption
fn encrypt<R1, R2, R3>(
    password: &[u8],
    format: Format,
    input: R1,
    nonce: Option<R2>,
    salt: Option<R3>,
) -> Result<Vec<u8>, String>
where
    R1: Read,
    R2: Read,
    R3: Read,
{
    // Read and deserialize the vault. Drop the handler so that we can write back to the same file
    let vault: Vault = match format {
        Format::Toml => toml::from_slice(&read_to_vec(input)?).map_err(|e| e.to_string())?,
        Format::Json => serde_json::from_reader(input).map_err(|e| e.to_string())?,
        Format::Yaml => serde_yaml::from_reader(input).map_err(|e| e.to_string())?,
    };
    let nonce = read_or_rng(nonce, libhimitsu::NONCE_LENGTH)?;
    let salt = read_or_rng(salt, 32)?;
    // Perform the encryption
    let encrypted = vault
        .encrypt(password, &salt, &nonce)
        .map_err(|e| e.to_string())?;

    Ok(encrypted)
}

/// Performs decryption
fn decrypt<R: Read>(input: R, password: &[u8]) -> Result<Vault, String> {
    let buffer = read_to_vec(input)?;
    // Decrypt the input
    Vault::decrypt(&buffer, password).map_err(|e| e.to_string())
}

/// Make a command line parser for options
fn make_parser<'a, 'b>() -> App<'a, 'b>
where
    'a: 'b,
{
    let encrypt = SubCommand::with_name("encrypt")
        .about("Encrypt a vault with the provided password.")
        .arg(
            Arg::with_name("nonce")
                .long("nonce")
                .help(
                    "Instead of generating a random NONCE for the encryption process, \
                     provide a path to a file containing the nonce. Use - to refer to STDIN",
                )
                .takes_value(true)
                .value_name("path"),
        )
        .arg(
            Arg::with_name("salt")
                .long("salt")
                .help(
                    "Instead of generating a random salt for the key derivation process, \
                     provide a path to a file containing the salt. Use - to refer to STDIN",
                )
                .takes_value(true)
                .value_name("path"),
        )
        .arg(
            Arg::with_name("password")
                .help(
                    "Instead of prompting for a password, use the password from the provided path \
                     instead. Use `-` to refer to STDIN",
                )
                .short("p")
                .long("password")
                .takes_value(true)
                .value_name("path"),
        )
        .arg(
            Arg::with_name("format")
                .help("Specify the format the decrypted vault is in.")
                .possible_values(&Format::possible_values())
                .default_value(Format::Toml.to_str())
                .short("f")
                .long("format")
                .takes_value(true)
                .value_name("format")
                .global(true),
        )
        .arg(
            Arg::with_name("input")
                .index(1)
                .help(
                    "Specifies the path to read the decrypted vault from. \
                     Defaults to STDIN. Use - to refer to STDIN",
                )
                .takes_value(true)
                .value_name("path"),
        )
        .arg(
            Arg::with_name("output")
                .index(2)
                .help(
                    "Specifies the path to write the encrypted vault to. \
                     Defaults to STDOUT. Use - to refer to STDOUT",
                )
                .takes_value(true)
                .value_name("path"),
        );

    let decrypt = SubCommand::with_name("decrypt")
        .about("Decrypt a vault with the provided password.")
        .arg(
            Arg::with_name("password")
                .help(
                    "Instead of prompting for a password, use the password from the provided path \
                     instead. Use `-` to refer to STDIN",
                )
                .short("p")
                .long("password")
                .takes_value(true)
                .value_name("path"),
        )
        .arg(
            Arg::with_name("format")
                .help("Specify the format the decrypted vault is in.")
                .possible_values(&Format::possible_values())
                .default_value(Format::Toml.to_str())
                .short("f")
                .long("format")
                .takes_value(true)
                .value_name("format")
                .global(true),
        )
        .arg(
            Arg::with_name("input")
                .index(1)
                .help(
                    "Specifies the path to read the encrypted vault from. \
                     Defaults to STDIN. Use - to refer to STDIN",
                )
                .takes_value(true)
                .value_name("path"),
        )
        .arg(
            Arg::with_name("output")
                .index(2)
                .help(
                    "Specifies the path to write the decrypted vault to. \
                     Defaults to STDOUT. Use - to refer to STDOUT",
                )
                .takes_value(true)
                .value_name("path"),
        );

    App::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!())
        .setting(AppSettings::SubcommandRequired)
        .setting(AppSettings::VersionlessSubcommands)
        .setting(AppSettings::PropagateGlobalValuesDown)
        .setting(AppSettings::InferSubcommands)
        .setting(AppSettings::ArgsNegateSubcommands)
        .global_setting(AppSettings::DontCollapseArgsInUsage)
        .global_setting(AppSettings::NextLineHelp)
        .about(
            "Launch applications using secrets encrypted inside \"vaults\". These vaults are\
             stored in an encrypted form.\
             Encryption keys are derived from passwords using `argon2i` and encryption is \
             performed with `ChaCha20-Poly1305`.",
        )
        .subcommand(encrypt)
        .subcommand(decrypt)
}

/// Gets a `Read` depending on the path. If the path is `-`, read from STDIN
fn input_reader(path: &str) -> Result<Box<Read>, String> {
    match path {
        "-" => Ok(Box::new(io::stdin())),
        path => {
            let file = File::open(path).map_err(|e| format!("Cannot open input file: {}", e))?;
            Ok(Box::new(file))
        }
    }
}

/// Gets a `Write` depending on the path. If the path is `-`, write to STDOUT
fn output_writer(path: &str) -> Result<Box<Write>, String> {
    match path {
        "-" => Ok(Box::new(io::stdout())),
        path => {
            let file = File::create(path).map_err(|e| format!("Cannot open output file: {}", e))?;
            Ok(Box::new(file))
        }
    }
}

/// Read a `Reader` to a vector of bytes
fn read_to_vec<R: Read>(mut reader: R) -> Result<Vec<u8>, String> {
    let mut buffer = Vec::new();
    let _ = reader.read_to_end(&mut buffer).map_err(|e| e.to_string())?;
    Ok(buffer)
}

/// Read some bytes from path, or randomly generate
fn read_or_rng<R: Read>(reader: Option<R>, length: usize) -> Result<Vec<u8>, String> {
    match reader {
        Some(reader) => read_to_vec(reader),
        None => {
            let mut buffer = vec![0; length];
            let mut rng = OsRng::new().map_err(|e| e.to_string())?;
            rng.fill_bytes(&mut buffer);
            Ok(buffer)
        }
    }
}

/// Serialize a vault to some formatted string
fn serialize_vault(vault: &Vault, format: Format) -> Result<String, String> {
    Ok(match format {
        Format::Toml => toml::to_string_pretty(&vault).map_err(|e| e.to_string())?,
        Format::Json => serde_json::to_string_pretty(&vault).map_err(|e| e.to_string())?,
        Format::Yaml => serde_yaml::to_string(&vault).map_err(|e| e.to_string())?,
    })
}

/// Counts the number of "dashes" or `-` in an Iterator of Options<S>
fn dash_count<'a, S, I>(iterator: I) -> usize
where
    S: AsRef<str> + 'a,
    I: Iterator<Item = &'a Option<S>>,
{
    iterator.fold(0, |acc, item| {
        acc + if item.is_some() && is_dash(item.as_ref().unwrap().as_ref()) {
            1
        } else {
            0
        }
    })
}

/// Returns whether a string is a dash "-"
fn is_dash(s: &str) -> bool {
    s == "-"
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Cursor;
    use std::ops::Fn;

    use toml;
    use libhimitsu::{self, Vault};

    static PASSWORD: &str = "password";

    fn zero_bytes(size: usize) -> Vec<u8> {
        vec![0; size]
    }

    fn zero_salt() -> Vec<u8> {
        zero_bytes(32)
    }

    fn zero_nonce() -> Vec<u8> {
        zero_bytes(libhimitsu::NONCE_LENGTH)
    }

    fn fixture() -> Vault {
        toml::from_str(toml_fixture()).expect("to work")
    }

    fn toml_fixture() -> &'static str {
        include_str!("../tests/fixtures/decrypted.toml")
    }

    fn yaml_fixture() -> &'static str {
        include_str!("../tests/fixtures/decrypted.yaml")
    }

    fn json_fixture() -> &'static str {
        include_str!("../tests/fixtures/decrypted.json")
    }

    fn encrypted_fixture() -> &'static [u8] {
        include_bytes!("../tests/fixtures/encrypted.bin")
    }

    fn to_cursor<F, T>(fixture: F) -> Cursor<T>
    where
        F: Fn() -> T,
        T: AsRef<[u8]>,
    {
        Cursor::new(fixture())
    }

    #[test]
    fn dash_counts_correctly() {
        assert_eq!(
            0,
            dash_count::<String, std::slice::Iter<Option<String>>>([].into_iter())
        );

        assert_eq!(
            0,
            dash_count::<String, std::slice::Iter<Option<String>>>([None, None, None].into_iter())
        );

        assert_eq!(
            2,
            dash_count([Some("test"), None, Some("-"), Some("-")].into_iter())
        );
    }

    #[test]
    fn toml_roundtrip() {
        let expected = fixture();

        let encrypted = encrypt(
            PASSWORD.as_bytes(),
            Format::Toml,
            to_cursor(toml_fixture),
            Some(to_cursor(zero_nonce)),
            Some(to_cursor(zero_salt)),
        ).expect("to not fail");

        let decrypted = decrypt(Cursor::new(encrypted), PASSWORD.as_bytes()).expect("to not fail");

        assert_eq!(expected, decrypted);
    }

    #[test]
    fn json_roundtrip() {
        let expected = fixture();

        let encrypted = encrypt(
            PASSWORD.as_bytes(),
            Format::Json,
            to_cursor(json_fixture),
            Some(to_cursor(zero_nonce)),
            Some(to_cursor(zero_salt)),
        ).expect("to not fail");

        let decrypted = decrypt(Cursor::new(encrypted), PASSWORD.as_bytes()).expect("to not fail");

        assert_eq!(expected, decrypted);
    }

    #[test]
    fn yaml_roundtrip() {
        let expected = fixture();

        let encrypted = encrypt(
            PASSWORD.as_bytes(),
            Format::Yaml,
            to_cursor(yaml_fixture),
            Some(to_cursor(zero_nonce)),
            Some(to_cursor(zero_salt)),
        ).expect("to not fail");

        let decrypted = decrypt(Cursor::new(encrypted), PASSWORD.as_bytes()).expect("to not fail");

        assert_eq!(expected, decrypted);
    }
}
