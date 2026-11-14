import "elf"
import "math"

rule ELF_UPX_or_Suspicious_Packed
{
    meta:
        description = "Detects UPX markers or high-entropy ELF files with packer-related section names"
        severity = "medium"
        category = "binary_anomaly"

    strings:
        //UPX (ultimate packer extender)
        $upx_magic = "UPX!" ascii
        $upx0 = ".upx0" ascii nocase
        $upx1 = ".upx1" ascii nocase
        $upx2 = ".upx2" ascii nocase

    condition:
        elf.number_of_sections > 0 and
        (
            $upx_magic and any of ($upx*) 
            or
            (
                filesize > 4096 and
                math.entropy(0, filesize) > 7.2 and
                any of ($upx*)
            )
        )
        //checks for entropy because of unpredictability
        //packed exec w high entropy = code has been compressed or encoded
}