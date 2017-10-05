#[macro_use]
extern crate clap;
extern crate libhimitsu;
extern crate rand;
extern crate rpassword;
extern crate serde;
extern crate serde_json;
extern crate serde_yaml;
extern crate toml;

use std::fs::File;
use std::io::{self, Read, Write};

use clap::{App, AppSettings, Arg, ArgMatches, SubCommand};
use libhimitsu::Vault;
use rand::{OsRng, Rng};

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

    let format = args.value_of("format").unwrap(); // should always give a value due to default

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

    // Read and deserialize the vault. Drop the handler so that we can write back to the same file
    let vault: Vault = {
        let input = input_reader(input.unwrap())?; // safe to unwrap

        // Deserialize the vault
        match format {
            "toml" => toml::from_slice(&read_to_vec(input)?).map_err(|e| e.to_string())?,
            "json" => serde_json::from_reader(input).map_err(|e| e.to_string())?,
            "yaml" => serde_yaml::from_reader(input).map_err(|e| e.to_string())?,
            _ => {
                unreachable!("Unknown format {}", format);
            }
        }
    };

    let nonce = match nonce {
        Some(path) => {
            let reader = input_reader(path)?;
            let buffer = read_to_vec(reader)?;
            if buffer.len() != libhimitsu::NONCE_LENGTH {
                Err(format!(
                    "The nonce must be {} bytes long",
                    libhimitsu::NONCE_LENGTH
                ))?;
            }
            buffer
        }
        None => {
            let mut buffer = vec![0; libhimitsu::NONCE_LENGTH];
            let mut rng = OsRng::new().map_err(|e| e.to_string())?;
            rng.fill_bytes(&mut buffer);
            buffer
        }
    };

    let salt = match salt {
        Some(path) => {
            let reader = input_reader(path)?;
            read_to_vec(reader)?
        }
        None => {
            let mut buffer = vec![0; 32]; // just 32 bytes long
            let mut rng = OsRng::new().map_err(|e| e.to_string())?;
            rng.fill_bytes(&mut buffer);
            buffer
        }
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

    // Perform the encryption
    let encrypted = vault
        .encrypt(password.as_bytes(), &salt, &nonce)
        .map_err(|e| e.to_string())?;

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

    let format = args.value_of("format").unwrap(); // should always give a value due to default

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

    // Read and decrypt the vault. Drop the handler so that we can write back to the same file
    let vault = {
        let input = input_reader(input.unwrap())?; // safe to unwrap
        let buffer = read_to_vec(input)?;
        // Decrypt the input
        Vault::decrypt(&buffer, password.as_bytes()).map_err(|e| e.to_string())?
    };

    // Serialize the vault
    let serialized = match format {
        "toml" => toml::to_string_pretty(&vault).map_err(|e| e.to_string())?,
        "json" => serde_json::to_string_pretty(&vault).map_err(|e| e.to_string())?,
        "yaml" => serde_yaml::to_string(&vault).map_err(|e| e.to_string())?,
        _ => {
            unreachable!("Unknown format {}", format);
        }
    };

    // Write
    {
        let mut output = output_writer(output.unwrap())?; // safe to unwrap
        let _ = output
            .write_all(serialized.as_bytes())
            .map_err(|e| e.to_string())?;
    }
    Ok(())
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
                .help("Specify the format the decrypted vault is in. By default, this is `toml`.")
                .possible_values(&["toml", "yaml", "json"])
                .default_value("toml")
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
                .help("Specify the format the decrypted vault is in. By default, this is `toml`.")
                .possible_values(&["toml", "yaml", "json"])
                .default_value("toml")
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

    // Test encrypt default format
}
