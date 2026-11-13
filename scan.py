
import yara
import os
from datetime import datetime
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
RULES_DIR = BASE_DIR / "CF-Rules" / "Linux"

binaries = yara.compile(filepath=str(RULES_DIR / "binaries/ELF_binary.yar"))
exploits = yara.compile(filepath=str(RULES_DIR / "exploits/exploit_kits_index.yar"))
malware = yara.compile(filepath=str(RULES_DIR / "malware/malware_index.yar"))
sus = yara.compile(filepath=str(RULES_DIR / "suspicious_activity/gen_suspicious_strings.yar"))
webshells = yara.compile(filepath=str(RULES_DIR / "webshells/webshells_index.yar"))

logfilepath = Path("/var/log/filewatch/log.txt")
logfilepath.parent.mkdir(parents=True, exist_ok=True)

time = datetime.now().isoformat()

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
        m_strings = []
        for string in match.strings:
            for instance in string.instances:
                m_strings.append(
                    f"{string.identifier}: {instance.matched_data!r}"
                )
                log.write(
                    f"[ALERT] {group}: {file} | "
                    f"Rule: {match.rule} | "
                    f"Matches: {', '.join(m_strings)}\n"
                        )


with open(logfilepath, 'w') as f:
    f.write(f"START TIME {time} \n")
    for group, config in targets.items():
        for directory in config["paths"]:
            for path in Path(directory).rglob("*"):
                if path.is_file():
                    try:
                        file_parsing(path,config["rules"],group,f)

                    except (yara.Error, OSError) as e:
                        f.write(f"Error scanning {path}: {e}\n")
                        continue

    f.write(f"END TIME {time} \n")
    f.close()