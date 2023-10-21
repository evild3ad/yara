/*
    Hunting Russian Intelligence "Snake" Malware
    The Snake implant is considered the most sophisticated cyber espionage tool designed and used by
    Center 16 of Russia's Federal Security Service (FSB) for long-term intelligence collection on sensitive
    targets.
*/

rule APTSnake {
    meta:
        author = "Matt Suiche (Magnet Forensics)"
        description = "Hunting Russian Intelligence Snake Malware"
        creation_date = "2023-05-10"
        threat_name = "Windows.Malware.Snake"
        reference = "https://media.defense.gov/2023/May/09/2003218554/-1/-1/0/JOINT_CSA_HUNTING_RU_INTEL_SNAKE_MALWARE_20230509.PDF"
        severity = 100
        scan_context = "memory"
        license = "MIT"
        os = "windows"

    // The original search only query those bytes in PAGE_EXECUTE_WRITECOPY VADs
    strings:
        $a1 = { 25 73 23 31 }
        $a2 = { 25 73 23 32 }
        $a3 = { 25 73 23 33 }
        $a4 = { 25 73 23 34 }
        $a5 = { 2e 74 6d 70 }
        $a6 = { 2e 73 61 76 }
        $a7 = { 2e 75 70 64 }

    condition:
        all of them
}