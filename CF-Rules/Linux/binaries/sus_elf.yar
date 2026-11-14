import "elf"

rule ELF_Writable_Executable_Section
{
    meta:
        description = "Detects ELF sections marked writable and executable"
        severity = "medium"
        category = "binary_anomaly"

    condition:
    //inspects elf metadata
        elf.number_of_sections > 0 and
    //checks that an ELF file has at least 1 program segment via iteration
    //if so. iterates through all of them and checks through each section
        for any i in (0..elf.number_of_sections - 1) :
        (
            //checks for write permission
            (elf.sections[i].flags & elf.SHF_WRITE) != 0 and
            //checks for exec permission
            (elf.sections[i].flags & elf.SHF_EXECINSTR) != 0
        )
        
}