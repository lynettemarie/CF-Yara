rule ELF_sus 
{
    meta:
        description = "Detects ELF files with a writable and executable load segment"
        author = "egg"
        severity = "medium"
    
    condition:
        //checks for total number of elf segments
        elf.number_of_segments > 0 and
        for any i in (0..elf.number_of_segments - 1) :
        (
            elf.segments[i].type == elf.PT_LOAD and
            (elf.segments[i].flags & elf.PF_W) != 0 and
            (elf.segments[i].flags & elf.PF_X) != 0
        )

}