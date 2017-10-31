#[macro_use]
extern crate clap;
#[macro_use]
extern crate error_chain;
extern crate libhimitsu;
extern crate rand;
extern crate rpassword;
extern crate serde;
extern crate serde_json;
extern crate serde_yaml;
extern crate toml;

#[cfg(test)]
extern crate tempdir;

use std::fs::File;
use std::io::{self, Read, Write};
use std::process;

use clap::{App, AppSettings, Arg, ArgMatches, SubCommand};
use libhimitsu::{Command, Vault};
use rand::{OsRng, Rng};

error_chain!{
    links {
        VaultError(libhimitsu::Error, libhimitsu::ErrorKind);
    }

    foreign_links {
        IOError(std::io::Error);
        CommandLineError(clap::Error);
        UnicodeError(std::string::FromUtf8Error);
        TomlSerializationError(toml::ser::Error);
        TomlDeserializationError(toml::de::Error);
        JsonError(serde_json::Error);
        YamlError(serde_yaml::Error);
    }
}

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
    let fail_silent = args.is_present("fail_silent");

    std::process::exit(match result {
        Ok(()) => 0,
        Err(e) => {
            let stderr = &mut ::std::io::stderr();
            let stderr_failure = "Error writing to stderr";
            writeln!(stderr, "error: {}", e).expect(stderr_failure);

            for e in e.iter().skip(1) {
                writeln!(stderr, "caused by: {}", e).expect(stderr_failure);
            }

            // The backtrace is not always generated. Try to run this example
            // with `RUST_BACKTRACE=1`.
            if let Some(backtrace) = e.backtrace() {
                writeln!(stderr, "backtrace: {:?}", backtrace).expect(stderr_failure);
            }

            if !fail_silent {
                println!("Press enter to continue.");
                read_stdin().expect("Enter to be pressed");
            }
            1
        }
    });
}

/// Wait for any input and throw away the input. Useful for "press enter to continue".
fn read_stdin() -> Result<()> {
    let mut stdin = io::stdin();
    let mut buffer = vec![0; 1];
    // Read one byte
    let _ = stdin.read_exact(&mut buffer)?;
    Ok(())
}

fn run_subcommand(args: &ArgMatches) -> Result<()> {
    match args.subcommand() {
        ("encrypt", Some(args)) => run_encrypt(args),
        ("decrypt", Some(args)) => run_decrypt(args),
        ("launch", Some(args)) => run_launch(args),
        _ => Err("Unknown command or missing options".to_string())?,
    }
}

fn run_encrypt(args: &ArgMatches) -> Result<()> {
    let input = args.value_of("input")
        .expect("Required argument is provided");
    let output = args.value_of("output")
        .expect("Required argument is provided");

    let nonce = args.value_of("nonce");
    let salt = args.value_of("salt");
    let password = args.value_of("password");

    let format = value_t!(args, "format", Format)?;

    if dash_count(
        [
            Some(&input),
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
        let input = input_reader(input)?;
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
                String::from_utf8(buffer)?
            }
            None => {
                let password = rpassword::prompt_password_stdout(
                    "Enter the password to encrypt the vault with: ",
                )?;

                let confirmation = rpassword::prompt_password_stdout("Confirm your password: ")?;

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
        let mut output = output_writer(output)?; // safe to unwrap
        let _ = output.write_all(&encrypted)?;
    }
    Ok(())
}

fn run_decrypt(args: &ArgMatches) -> Result<()> {
    let input = args.value_of("input")
        .expect("Required argument is provided");
    let output = args.value_of("output")
        .expect("Required argument is provided");

    let password = args.value_of("password");

    let format = value_t!(args, "format", Format)?;

    if dash_count([Some(&input), password.as_ref()].into_iter()) > 1 {
        Err("Only one input source can be from STDIN")?
    }

    let password = match password {
        Some(path) => {
            let reader = input_reader(path)?;
            let buffer = read_to_vec(reader)?;
            String::from_utf8(buffer)?
        }
        None => {
            rpassword::prompt_password_stdout("Enter the password to decrypt the vault with: ")?
        }
    };

    let input = input_reader(input)?;

    // Read and decrypt the vault. Drop the handler so that we can write back to the same file
    let vault = decrypt(input, password.as_bytes())?;

    // Serialize the vault
    let serialized = serialize_vault(&vault, format)?;

    // Write
    {
        let mut output = output_writer(output)?;
        let _ = output.write_all(serialized.as_bytes())?;
    }
    Ok(())
}

fn run_launch(args: &ArgMatches) -> Result<()> {
    let input = args.value_of("input")
        .expect("Required argument is provided");

    let item_name = args.value_of("item")
        .expect("Required argument is provided");
    let password = args.value_of("password");

    if dash_count([Some(&input), password.as_ref()].into_iter()) > 1 {
        Err("Only one input source can be from STDIN")?
    }

    let password = match password {
        Some(path) => {
            let reader = input_reader(path)?;
            let buffer = read_to_vec(reader)?;
            String::from_utf8(buffer)?
        }
        None => {
            rpassword::prompt_password_stdout("Enter the password to decrypt the vault with: ")?
        }
    };

    let input = input_reader(input)?;
    let command = get_command(input, password.as_bytes(), &item_name)?;
    let mut command = process::Command::from(command);
    let _ = command.spawn()?;
    Ok(())
}

/// Performs the encryption
fn encrypt<R1, R2, R3>(
    password: &[u8],
    format: Format,
    input: R1,
    nonce: Option<R2>,
    salt: Option<R3>,
) -> Result<Vec<u8>>
where
    R1: Read,
    R2: Read,
    R3: Read,
{
    // Read and deserialize the vault. Drop the handler so that we can write back to the same file
    let vault = deserialize_vault(input, format)?;
    let nonce = read_or_rng(nonce, libhimitsu::NONCE_LENGTH)?;
    let salt = read_or_rng(salt, 32)?;
    // Perform the encryption
    let encrypted = vault.encrypt(password, &salt, &nonce)?;

    Ok(encrypted)
}

/// Performs decryption
fn decrypt<R: Read>(input: R, password: &[u8]) -> Result<Vault> {
    let buffer = read_to_vec(input)?;
    // Decrypt the input
    Ok(Vault::decrypt(&buffer, password)?)
}

fn get_command<R: Read>(input: R, password: &[u8], item_name: &str) -> Result<Command> {
    let vault = decrypt(input, password)?;

    let item = vault
        .himitsu
        .iter()
        .find(|himitsu| himitsu.name == item_name)
        .ok_or_else(|| format!("{} was not found in the vault", item_name))?;

    Ok(item.apply()?)
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
                .empty_values(false)
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
                .empty_values(false)
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
                .empty_values(false)
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
                .empty_values(false)
                .value_name("format")
                .global(true),
        )
        .arg(
            Arg::with_name("input")
                .index(1)
                .help(
                    "Specifies the path to read the decrypted vault from. \
                     Use - to refer to STDIN",
                )
                .takes_value(true)
                .value_name("input_path")
                .empty_values(false)
                .required(true),
        )
        .arg(
            Arg::with_name("output")
                .index(2)
                .help(
                    "Specifies the path to write the encrypted vault to. \
                     Use - to refer to STDOUT",
                )
                .takes_value(true)
                .value_name("output_path")
                .empty_values(false)
                .required(true),
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
                .empty_values(false)
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
                .empty_values(false)
                .global(true),
        )
        .arg(
            Arg::with_name("input")
                .index(1)
                .help(
                    "Specifies the path to read the encrypted vault from. \
                     Use - to refer to STDIN",
                )
                .takes_value(true)
                .value_name("input_path")
                .empty_values(false)
                .required(true),
        )
        .arg(
            Arg::with_name("output")
                .index(2)
                .help(
                    "Specifies the path to write the decrypted vault to. \
                     Use - to refer to STDOUT",
                )
                .takes_value(true)
                .value_name("output_path")
                .empty_values(false)
                .required(true),
        );

    let launch = SubCommand::with_name("launch")
        .about(
            "Launch applications from a vault with the decryption password and item name. \n\n\
             Hint: You can use `decrypt` to view the contents of your vault. Simply use `-`\
             to print the output to STDOUT",
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
                .empty_values(false)
                .value_name("path"),
        )
        .arg(
            Arg::with_name("input")
                .index(1)
                .help(
                    "Specifies the path to read the encrypted vault from. \
                     Use - to refer to STDIN",
                )
                .takes_value(true)
                .value_name("input_path")
                .empty_values(false)
                .required(true),
        )
        .arg(
            Arg::with_name("item")
                .index(2)
                .help("Specifies item to launch.")
                .takes_value(true)
                .value_name("item")
                .empty_values(false)
                .required(true),
        );

    App::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!())
        .setting(AppSettings::SubcommandRequired)
        .setting(AppSettings::VersionlessSubcommands)
        .setting(AppSettings::InferSubcommands)
        .global_setting(AppSettings::DontCollapseArgsInUsage)
        .global_setting(AppSettings::NextLineHelp)
        .about(
            "Launch applications using secrets encrypted inside \"vaults\". These vaults are\
             stored in an encrypted form.\
             Encryption keys are derived from passwords using `argon2i` and encryption is \
             performed with `ChaCha20-Poly1305`.",
        )
        .arg(Arg::with_name("fail_silent").long("fail-silent").help(
            "Instead of asking for the user to confirm any failure, \
             exit immediately on failure silently.",
        ))
        .subcommand(encrypt)
        .subcommand(decrypt)
        .subcommand(launch)
}

/// Gets a `Read` depending on the path. If the path is `-`, read from STDIN
fn input_reader(path: &str) -> Result<Box<Read>> {
    match path {
        "-" => Ok(Box::new(io::stdin())),
        path => {
            let file = File::open(path).map_err(|e| format!("Cannot open input file: {}", e))?;
            Ok(Box::new(file))
        }
    }
}

/// Gets a `Write` depending on the path. If the path is `-`, write to STDOUT
fn output_writer(path: &str) -> Result<Box<Write>> {
    match path {
        "-" => Ok(Box::new(io::stdout())),
        path => {
            let file = File::create(path).map_err(|e| format!("Cannot open output file: {}", e))?;
            Ok(Box::new(file))
        }
    }
}

/// Read a `Reader` to a vector of bytes
fn read_to_vec<R: Read>(mut reader: R) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();
    let _ = reader.read_to_end(&mut buffer)?;
    Ok(buffer)
}

/// Read some bytes from path, or randomly generate
fn read_or_rng<R: Read>(reader: Option<R>, length: usize) -> Result<Vec<u8>> {
    match reader {
        Some(reader) => read_to_vec(reader),
        None => {
            let mut buffer = vec![0; length];
            let mut rng = OsRng::new()?;
            rng.fill_bytes(&mut buffer);
            Ok(buffer)
        }
    }
}

/// Serialize a vault to some formatted string
fn serialize_vault(vault: &Vault, format: Format) -> Result<String> {
    Ok(match format {
        Format::Toml => toml::to_string_pretty(&vault)?,
        Format::Json => serde_json::to_string_pretty(&vault)?,
        Format::Yaml => serde_yaml::to_string(&vault)?,
    })
}

/// Deserialize a vault from a Reader
fn deserialize_vault<R: Read>(reader: R, format: Format) -> Result<Vault> {
    let vault: Vault = match format {
        Format::Toml => toml::from_slice(&read_to_vec(reader)?)?,
        Format::Json => serde_json::from_reader(reader)?,
        Format::Yaml => serde_yaml::from_reader(reader)?,
    };
    Ok(vault)
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

    use std::fs::File;
    use std::io::{Cursor, Seek};
    use std::ops::Fn;
    use std::path::PathBuf;

    use toml;
    use libhimitsu::{self, EncryptedVault, Vault};
    use tempdir::TempDir;

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

    fn tempdir() -> TempDir {
        TempDir::new("himitsu").expect("To create a temporary directory")
    }

    fn tempfile(tempdir: &TempDir, name: &str) -> PathBuf {
        tempdir.path().join(name)
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
    fn decryption_works() {
        let expected = fixture();

        let decrypted =
            decrypt(to_cursor(encrypted_fixture), PASSWORD.as_bytes()).expect("to not fail");
        assert_eq!(expected, decrypted);
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

    #[test]
    fn encrypt_uses_provided_salt_and_nonce() {
        let encrypted = encrypt(
            PASSWORD.as_bytes(),
            Format::Toml,
            to_cursor(toml_fixture),
            Some(to_cursor(zero_nonce)),
            Some(to_cursor(zero_salt)),
        ).expect("to not fail");

        let unpacked = EncryptedVault::unpack(&encrypted).expect("to succeed");

        assert!(unpacked.salt.iter().all(|byte| *byte == 0u8));
        assert!(unpacked.nonce.iter().all(|byte| *byte == 0u8));
    }

    #[test]
    #[should_panic(expected = "Only one input source can be from STDIN")]
    /// Only one input from STDIN is allowed
    fn encrypt_stdin_validated_correctly() {
        let parser = make_parser();
        let args = vec!["himitsu", "encrypt", "--nonce=-", "--password=-", "-", "-"];
        let matches = parser
            .get_matches_from_safe(args)
            .expect("parsing to succeed");
        let subcommand = matches
            .subcommand_matches("encrypt")
            .expect("to be encrypt subcommand");
        run_encrypt(&subcommand).unwrap();
    }

    #[test]
    #[should_panic(expected = "Only one input source can be from STDIN")]
    /// Only one input from STDIN is allowed
    fn decrypt_stdin_validated_correctly() {
        let parser = make_parser();
        let args = vec!["himitsu", "decrypt", "--password=-", "-", "-"];
        let matches = parser
            .get_matches_from_safe(args)
            .expect("parsing to succeed");
        let subcommand = matches
            .subcommand_matches("decrypt")
            .expect("to be decrypt subcommand");
        run_decrypt(&subcommand).unwrap();
    }

    #[test]
    #[should_panic(expected = "Only one input source can be from STDIN")]
    /// Only one input from STDIN is allowed
    fn launch_stdin_validated_correctly() {
        let parser = make_parser();
        let args = vec!["himitsu", "launch", "--password=-", "-", "cat"];
        let matches = parser
            .get_matches_from_safe(args)
            .expect("parsing to succeed");
        let subcommand = matches
            .subcommand_matches("launch")
            .expect("to be decrypt subcommand");
        run_launch(&subcommand).unwrap();
    }

    #[test]
    fn encrypt_decrypt_roundtrip_toml() {
        let directory = tempdir();
        let decrypted_path = tempfile(&directory, "decrypted.toml");
        let encrypted_path = tempfile(&directory, "encrypted.bin");
        let password_path = tempfile(&directory, "password.txt");

        {
            let mut decrypted = File::create(&decrypted_path).expect("to create successfully");
            let mut password = File::create(&password_path).expect("to create successfully");
            decrypted
                .write_all(toml_fixture().as_bytes())
                .expect("to be successful");
            password
                .write_all(PASSWORD.as_bytes())
                .expect("to be successful");
        }

        let parser = make_parser();
        let matches = parser
            .get_matches_from_safe(vec![
                "himitsu",
                "encrypt",
                "--password",
                password_path.to_str().expect("to exist"),
                "--format=toml",
                decrypted_path.to_str().expect("to exist"),
                encrypted_path.to_str().expect("to exist"),
            ])
            .expect("parsing to succeed");
        let subcommand = matches
            .subcommand_matches("encrypt")
            .expect("to be encrypt subcommand");

        run_encrypt(&subcommand).expect("to succeed");

        let parser = make_parser();
        let matches = parser
            .get_matches_from_safe(vec![
                "himitsu",
                "decrypt",
                "--password",
                password_path.to_str().expect("to exist"),
                "--format=toml",
                encrypted_path.to_str().expect("to exist"),
                decrypted_path.to_str().expect("to exist"),
            ])
            .expect("parsing to succeed");
        let subcommand = matches
            .subcommand_matches("decrypt")
            .expect("to be decrypt subcommand");
        run_decrypt(&subcommand).expect("to succeed");

        let expected = fixture();
        let mut decrypted = File::open(&decrypted_path).expect("to open decrypted file");
        decrypted
            .seek(std::io::SeekFrom::Start(0))
            .expect("to succeed");
        let actual =
            deserialize_vault(&mut decrypted, Format::Toml).expect("to deserialize correctly");
        assert_eq!(actual, expected);
    }

    #[test]
    fn encrypt_decrypt_roundtrip_json() {
        let directory = tempdir();
        let decrypted_path = tempfile(&directory, "decrypted.json");
        let encrypted_path = tempfile(&directory, "encrypted.bin");
        let password_path = tempfile(&directory, "password.txt");

        {
            let mut decrypted = File::create(&decrypted_path).expect("to create successfully");
            let mut password = File::create(&password_path).expect("to create successfully");
            decrypted
                .write_all(json_fixture().as_bytes())
                .expect("to be successful");
            password
                .write_all(PASSWORD.as_bytes())
                .expect("to be successful");
        }

        let parser = make_parser();
        let matches = parser
            .get_matches_from_safe(vec![
                "himitsu",
                "encrypt",
                "--password",
                password_path.to_str().expect("to exist"),
                "--format=json",
                decrypted_path.to_str().expect("to exist"),
                encrypted_path.to_str().expect("to exist"),
            ])
            .expect("parsing to succeed");
        let subcommand = matches
            .subcommand_matches("encrypt")
            .expect("to be encrypt subcommand");

        run_encrypt(&subcommand).expect("to succeed");

        let parser = make_parser();
        let matches = parser
            .get_matches_from_safe(vec![
                "himitsu",
                "decrypt",
                "--password",
                password_path.to_str().expect("to exist"),
                "--format=json",
                encrypted_path.to_str().expect("to exist"),
                decrypted_path.to_str().expect("to exist"),
            ])
            .expect("parsing to succeed");
        let subcommand = matches
            .subcommand_matches("decrypt")
            .expect("to be decrypt subcommand");
        run_decrypt(&subcommand).expect("to succeed");

        let expected = fixture();
        let mut decrypted = File::open(&decrypted_path).expect("to open decrypted file");
        decrypted
            .seek(std::io::SeekFrom::Start(0))
            .expect("to succeed");
        let actual =
            deserialize_vault(&mut decrypted, Format::Json).expect("to deserialize correctly");
        assert_eq!(actual, expected);
    }

    #[test]
    fn encrypt_decrypt_roundtrip_yaml() {
        let directory = tempdir();
        let decrypted_path = tempfile(&directory, "decrypted.yaml");
        let encrypted_path = tempfile(&directory, "encrypted.bin");
        let password_path = tempfile(&directory, "password.txt");

        {
            let mut decrypted = File::create(&decrypted_path).expect("to create successfully");
            let mut password = File::create(&password_path).expect("to create successfully");
            decrypted
                .write_all(yaml_fixture().as_bytes())
                .expect("to be successful");
            password
                .write_all(PASSWORD.as_bytes())
                .expect("to be successful");
        }

        let parser = make_parser();
        let matches = parser
            .get_matches_from_safe(vec![
                "himitsu",
                "encrypt",
                "--password",
                password_path.to_str().expect("to exist"),
                "--format=yaml",
                decrypted_path.to_str().expect("to exist"),
                encrypted_path.to_str().expect("to exist"),
            ])
            .expect("parsing to succeed");
        let subcommand = matches
            .subcommand_matches("encrypt")
            .expect("to be encrypt subcommand");

        run_encrypt(&subcommand).expect("to succeed");

        let parser = make_parser();
        let matches = parser
            .get_matches_from_safe(vec![
                "himitsu",
                "decrypt",
                "--password",
                password_path.to_str().expect("to exist"),
                "--format=yaml",
                encrypted_path.to_str().expect("to exist"),
                decrypted_path.to_str().expect("to exist"),
            ])
            .expect("parsing to succeed");
        let subcommand = matches
            .subcommand_matches("decrypt")
            .expect("to be decrypt subcommand");
        run_decrypt(&subcommand).expect("to succeed");

        let expected = fixture();
        let mut decrypted = File::open(&decrypted_path).expect("to open decrypted file");
        decrypted
            .seek(std::io::SeekFrom::Start(0))
            .expect("to succeed");
        let actual =
            deserialize_vault(&mut decrypted, Format::Yaml).expect("to deserialize correctly");
        assert_eq!(actual, expected);
    }

    #[test]
    fn encrypt_decrypt_roundtrip_same_file() {
        let directory = tempdir();
        let decrypted_path = tempfile(&directory, "vault");
        let encrypted_path = tempfile(&directory, "vault");
        let password_path = tempfile(&directory, "password.txt");

        {
            let mut decrypted = File::create(&decrypted_path).expect("to create successfully");
            let mut password = File::create(&password_path).expect("to create successfully");
            decrypted
                .write_all(toml_fixture().as_bytes())
                .expect("to be successful");
            password
                .write_all(PASSWORD.as_bytes())
                .expect("to be successful");
        }

        let parser = make_parser();
        let matches = parser
            .get_matches_from_safe(vec![
                "himitsu",
                "encrypt",
                "--password",
                password_path.to_str().expect("to exist"),
                "--format=toml",
                decrypted_path.to_str().expect("to exist"),
                encrypted_path.to_str().expect("to exist"),
            ])
            .expect("parsing to succeed");
        let subcommand = matches
            .subcommand_matches("encrypt")
            .expect("to be encrypt subcommand");

        run_encrypt(&subcommand).expect("to succeed");

        let parser = make_parser();
        let matches = parser
            .get_matches_from_safe(vec![
                "himitsu",
                "decrypt",
                "--password",
                password_path.to_str().expect("to exist"),
                "--format=toml",
                encrypted_path.to_str().expect("to exist"),
                decrypted_path.to_str().expect("to exist"),
            ])
            .expect("parsing to succeed");
        let subcommand = matches
            .subcommand_matches("decrypt")
            .expect("to be decrypt subcommand");
        run_decrypt(&subcommand).expect("to succeed");

        let expected = fixture();
        let mut decrypted = File::open(&decrypted_path).expect("to open decrypted file");
        decrypted
            .seek(std::io::SeekFrom::Start(0))
            .expect("to succeed");
        let actual =
            deserialize_vault(&mut decrypted, Format::Toml).expect("to deserialize correctly");
        assert_eq!(actual, expected);
    }

    #[test]
    fn launch_creates_the_right_command() {
        let encrypted = to_cursor(encrypted_fixture);
        let command = get_command(encrypted, PASSWORD.as_bytes(), "cat").expect("to succeed");
        let expected = Command {
            executeable: "cat".to_string(),
            current_directory: Some(From::from("/bin")),
            arguments: vec!["/etc/hosts".to_string()],
        };
        assert_eq!(command, expected);
    }
}
