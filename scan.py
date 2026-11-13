
import yara
import argparse
from datetime import datetime
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
RULES_DIR = BASE_DIR / "CF-Rules" / "Linux"
LOG_FILE = Path("var/log/filewatch/log.txt")
MAX_FILE_SIZE = 100 * 1024 * 1024 #Max file sixe is 100 MB to reduce CPU usage

#binaries = yara.compile(filepath=str(RULES_DIR / "binaries/ELF_binary.yar"))
exploits = yara.compile(filepath=str(RULES_DIR / "exploits/exploit_kits_index.yar"))
malware = yara.compile(filepath=str(RULES_DIR / "malware/malware_index.yar"))
sus = yara.compile(filepath=str(RULES_DIR / "suspicious_activity/gen_suspicious_strings.yar"))
webshells = yara.compile(filepath=str(RULES_DIR / "webshells/webshells_index.yar"))

logfilepath = Path("/var/log/filewatch/log.txt")
logfilepath.parent.mkdir(parents=True, exist_ok=True)

#Layer 1 = runs more frequently on higher priority files
#Layer 2 = runs periodically to ensure that all other files are ok 
SCAN_LAYERS = {
     1: { 
        "exploits": {
            "rules": exploits,
            "paths": ["/tmp", "/var/tmp", "/dev/shm"]
        },

        "malware": {
            "rules": malware,
            "paths": ["/tmp", "/var/tmp", "/dev/shm", "/usr/local/bin", "/usr/local/lib", "/usr/blueteam"]
        },

        "sus": {
            "rules": sus,
            "paths": ["/tmp", "/var/tmp", "/dev/shm", "/etc/systemd/system", "/etc/cron.d", "/etc/profile.d"]
        },

        "webshells": {
            "rules": webshells,
            "paths": ["/var/www", "/srv"]
        }
    },

    2: {
        "exploits": {
            "rules": exploits,
            "paths": ["/home"]
        },

        "malware": {
            "rules": malware,
            "paths": ["/usr/bin", "/usr/sbin", "/usr/lib","/usr/lib64","/opt","/home","/root"]
        },

        "sus": {
            "rules": sus,
            "paths": ["/home","/root","/var/spool/cron"]
        }
    }
}


def file_parsing(file, rules, group, log):
     for match in rules.match(filepath=str(file)):
        m_strings = {}
        for string in match.strings:
            for instance in string.instances:
                key = (string.identifier, instance.matched_data)
                m_strings[key] = m_strings.get(key, 0) + 1

        if not m_strings:
            continue

        log.write(
            f"[ALERT] {group}: {file} | "
            f"Rule: {match.rule} | "
            f"Matches: "
            f"{', '.join(
                f'{identifier}: {data!r} (Count: {count})'
                for (identifier, data), count in m_strings.items()
            )}\n"
        )

def scan_layer(layer):
    targets = SCAN_LAYERS[layer]
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    log_file = LOG_FILE.parent / f"layer{layer}_log.txt" #added so that each scan layer has its own file

    with open(log_file, 'w') as f:
        f.write(f"START TIME {datetime.now().isoformat()} & LAYER {layer} \n")
        for group, config in targets.items():
            for directory in config["paths"]:
                base_path = Path(directory)
                if not base_path.exists():
                    continue

                for path in base_path.rglob("*"):
                    try:
                        if path.is_file() and path.stat().st_size <= MAX_FILE_SIZE:
                            file_parsing(path,config["rules"],group,f)
        
                    except (yara.Error, OSError) as e:
                        f.write( f"[ERROR] {path}: {e}\n")

        f.write(f"END TIME {datetime.now().isoformat()} \n")

#dividing layers into 2 to automate

parser = argparse.ArgumentParser(
    description="Linux YARA Scanner"
)

parser.add_argument(
    "--layer",
    type=int,
    choices=[1, 2],
    required=True,
    help="Select scan layer: 1 or 2"
)

args = parser.parse_args()

scan_layer(args.layer)
