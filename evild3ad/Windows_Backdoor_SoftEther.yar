rule Windows_Backdoor_SoftEther : SoftEther {
	meta:
		description = "Detects SoftEther VPN Bridge"
		author = "Martin Willing (https://lethal-forensics.com)"
		id = "df42c84c-b64d-4918-88db-6bad5a2d75ba"
		creation_date = "2026-08-31"
		last_modified = "2026-08-31"
		threat_name = "Windows.Backdoor.SoftEther"
		reference_sample = "90E70C0B04ECB9DFA1D5C60FE7DE901846EBF0B54754EA12DDE1CCB77623A6E8"
		severity = 100
		arch_context = "x64"
		scan_context = "memory"
		os = "windows"
	strings:
		$a1 = "declare CascadeList" ascii fullword
		$a2 = "string Hostname" ascii fullword
		$a3 = "string HubName" ascii fullword
		$a4 = "SVC_VPNBRIDGE_NAME"
		$a5 = "bool EnableSoftEtherKernelModeDriver true" ascii fullword
		$a6 = "VPN Client Adapter - %s" ascii fullword
		$a7 = "SoftEther_VPN" ascii fullword
		$a8 = "Web Site: https://www.softether.org/"
		$a9 = "Copyright (c) SoftEther Corporation. All Rights Reserved."
		$a10 = "[HUB \"BRIDGE\"]" ascii fullword
	condition:
		3 of them
}