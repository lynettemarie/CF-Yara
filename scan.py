
import yara
import os 
from datetime import datetime
from pathlib import Path

rulesfilepath = Path.home() / "Downloads" / "logactions.yar"
rules = yara.compile(filepath= str(rulesfilepath))
#path of wherever the yara rules will be placed
#we can also hard code this

binaries = yara.compile(filepath="./Linux/binaries/ELF_binary.yar")

exploits = yara.compile(filepath="./Linux/exploits/exploit_kits_index.yar")

malware = yara.compile(filepath="./Linux/malware/malware_index.yar")

sus = yara.compile(filepath= './Linux/suspicious_activity/gen_suspicious_strings.yar')

webshells = yara.compile(filepath= "./Linux/webshells/webshells_index.yar")

rootkits = yara.compile(filepath= "./Linux/webshells/webshells_index.yar")

targets = {
    "system_binaries": { 
        "rules": binaries,
        "paths": ["/usr/bin", "/usr/local/bin", "/bin" ]
    },

    "exploits": {
        "rules": exploits,
        "paths": ["/filehere/" ]
    },

    "malware": {
            "rules": malware,
            "paths": [ "/filehere/" ]
        },

    "sus": {
            "rules": sus,
            "paths": ["/filehere/"]
        },

    "webshells": {
            "rules": webshells,
            "paths": ["/filehere/"]
        },

    "rootkits": {
                "rules": webshells,
                "paths": ["/filehere/"]
            }
}


logfilepath = Path.home() / "Downloads" / "log.txt"
time = datetime.now().isoformat()
#gets the file path, outputs whether or not there is a yara match

def file_parsing(file, rules, group, log):
     for match in rules.match(filepath=str(file)):
        log.write(f"[ALERT] {group}: {file} - {match.rule}\n")


with open(logfilepath, 'w') as f:
    f.write(time+ "\n")
    for group, config in targets.items():
        for directory in config["paths"]:
            for path in Path(directory).rglob("*"):
                if path.is_file():
                    try:
                        file_parsing(path,config["rules"],group,f)

                    except yara.Error as e:
                        f.write(f"Error scanning {path}: {e}\n")
                        continue