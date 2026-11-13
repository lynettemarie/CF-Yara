
import yara
import os
from datetime import datetime
from pathlib import Path

binaries = yara.compile(filepath="./CF-Rules/Linux/binaries/ELF_binary.yar")
exploits = yara.compile(filepath="./CF-Rules/Linux/exploits/exploit_kits_index.yar")
malware = yara.compile(filepath="./CF-Rules/Linux/malware/malware_index.yar")
sus = yara.compile(filepath= './CF-Rules/Linux/suspicious_activity/gen_suspicious_strings.yar')
webshells = yara.compile(filepath= "./CF-Rules/Linux/webshells/webshells_index.yar")
logfilepath = Path.home() / "Downloads" / "log.txt"
time = datetime.now().isoformat()
#gets the file path, outputs whether or not there is a yara match
false_positive = 0
targets = {
    "system_binaries": { 
        "rules": binaries,
        "paths": ["/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin"]
    },

    "exploits": {
        "rules": exploits,
        "paths": ["/tmp", "/var/tmp", "/dev/shm", "/home"]
    },

    "malware": {
            "rules": malware,
            "paths": [ "/usr/bin", "/usr/sbin", "/usr/blueteam", "/usr/local/bin",
                      "/usr/lib","/usr/lib64", "/tmp", "/var/tmp", "/dev/shm", "/home", "/root",
                      "/opt", "/etc/cron.d", "/var/spool/cron"]
        },

    "sus": {
            "rules": sus,
            "paths": ["/tmp", "/var/tmp", "/dev/shm", "/usr/local/bin", "/etc/systemd/system", 
                      "/etc/cron.d", "/etc/profile.d", "/var/spool/cron", "/home", "/root"]
        },

    "webshells": {
            "rules": webshells,
            "paths": ["/var/www", "/srv"]
        },
}



def file_parsing(file, rules, group, log):
     for match in rules.match(filepath=str(file)):
        for string in match.strings:
            for instance in string.instances:

                log.write(
                    f"[ALERT] {group}: {file} | "
                    f"Rule: {match.rule} | "
                    f"String: {string.identifier} | "
                    f"Offset: {instance.offset} | "
                    f"Matched data: {instance.matched_data!r}\n"
                        )


with open(logfilepath, 'w') as f:
    f.write(time + "\n")
    for group, config in targets.items():
        for directory in config["paths"]:
            for path in Path(directory).rglob("*"):
                if path.is_file():
                    try:
                        file_parsing(path,config["rules"],group,f)

                    except (yara.Error, OSError) as e:
                        f.write(f"Error scanning {path}: {e}\n")
                        continue
