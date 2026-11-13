rule ELF_binary 
{
    meta:
        description = "Detects for suspicious exec and known malware indicators"
        Author = "egg"
        operating_system = "Linux"

     strings:
        $elf = { 7F 45 4C 46 }

        $shell = "/bin/sh" ascii
        $execve = "execve" ascii
        $system = "system" ascii
        $popen = "popen" ascii

        $socket = "socket" ascii
        $connect = "connect" ascii

    condition:
        $elf at 0 and
        (
            2 of ($shell, $execve, $system, $popen) and
            1 of ($socket, $connect)
        )
}



 

