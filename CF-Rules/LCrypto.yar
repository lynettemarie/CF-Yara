rule LCrypto.yar
{ 
    meta:
        description = "Detects potential cryptocurrency mining indicators"
        severity = "Medium"
    
    strings:
        $xmrig = "XMRig" ascii nocase
        $stratum = "stratum+tcp://" ascii nocase
        $mining = "mining.subscribe" ascii nocase

    condition:
        2 of them

}