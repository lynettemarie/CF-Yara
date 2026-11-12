
import yara
import os 
from datetime import datetime
from pathlib import Path

rulesfilepath = Path.home() / "Downloads" / "logactions.yar"
rules = yara.compile(filepath= str(rulesfilepath))
#path of wherever the yara rules will be placed
#we can also hard code this

targets = [
    "/usr/bin",
    "/usr/local/bin",
]

logfilepath = Path.home() / "Downloads" / "log.txt"
time = datetime.now().isoformat()
#gets the file path, outputs whether or not there is a yara match
'''
with open(logfilepath, 'w') as f:
    f.write(time+ "\n")
    for target in targets:
        for path in Path(target).rglob("*"):
            if path.is_file():
                try:
                    matches = rules.match(filepath=path)
                except yara.Error as e:
                    f.write(f"Error scanning {path}: {e}\n")
                    continue

                for match in matches:
                    f.write(f"File: {path}\n")
                    f.write(f"Rule: {match.rule} (namespace: {match.namespace})\n")
'''