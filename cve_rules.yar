rule MSIETabularActivex
{
        meta:
                ref = "CVE-2010-0805"
                impact = 7
                hide = true
                author = "@d3t0n4t0r"
        strings:
                $cve20100805_1 = "333C7BC4-460F-11D0-BC04-0080C7055A83" nocase fullword
                $cve20100805_2 = "DataURL" nocase fullword
                $cve20100805_3 = "true"
        condition:
                ($cve20100805_1 and $cve20100805_3) or (all of them)
}

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule JavaDeploymentToolkit
{
   meta:
      ref = "CVE-2010-0887"
      impact = 7
      author = "@d3t0n4t0r"
   strings:
      $cve20100887_1 = "CAFEEFAC-DEC7-0000-0000-ABCDEFFEDCBA" nocase fullword
      $cve20100887_2 = "document.createElement(\"OBJECT\")" nocase fullword
      $cve20100887_3 = "application/npruntime-scriptable-plugin;deploymenttoolkit" nocase fullword
      $cve20100887_4 = "application/java-deployment-toolkit" nocase fullword
      $cve20100887_5 = "document.body.appendChild(" nocase fullword
      $cve20100887_6 = "launch("
      $cve20100887_7 = "-J-jar -J" nocase fullword
   condition:
      3 of them
}
rule FlashNewfunction: decodedPDF
{
   meta:  
      ref = "CVE-2010-1297"
      hide = true
      impact = 5 
      ref = "http://blog.xanda.org/tag/jsunpack/"
   strings:
      $unescape = "unescape" fullword nocase
      $shellcode = /%u[A-Fa-f0-9]{4}/
      $shellcode5 = /(%u[A-Fa-f0-9]{4}){5}/
      $cve20101297 = /\/Subtype ?\/Flash/
   condition:
      ($unescape and $shellcode and $cve20101297) or ($shellcode5 and $cve20101297)
}

/*
*
* Signature for the CVE-2012-0158 used in KeyBoy operation
* Ref https://citizenlab.org/2016/11/parliament-keyboy/
*
*/
rule CVE_2012_0158_KeyBoy {
  meta:
      author = "Etienne Maynier <etienne@citizenlab.ca>"
      description = "CVE-2012-0158 variant"
      file = "8307e444cad98b1b59568ad2eba5f201"

  strings:
      $a = "d0cf11e0a1b11ae1000000000000000000000000000000003e000300feff09000600000000000000000000000100000001" nocase // OLE header
      $b = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" nocase // junk data
      $c = /5(\{\\b0\}|)[ ]*2006F00(\{\\b0\}|)[ ]*6F007(\{\\b0\}|)[ ]*400200045(\{\\b0\}|)[ ]*006(\{\\b0\}|)[ ]*E007(\{\\b0\}|)[ ]*400720079/ nocase
      $d = "MSComctlLib.ListViewCtrl.2"
      $e = "ac38c874503c307405347aaaebf2ac2c31ebf6e8e3" nocase //decoding shellcode


  condition:
      all of them
}

rule CVE_2013_0422
{
        meta:
                description = "Java Applet JMX Remote Code Execution"
                cve = "CVE-2013-0422"
                ref = "http://pastebin.com/JVedyrCe"
                author = "adnan.shukor@gmail.com"
                date = "12-Jan-2013"
                version = "1"
                impact = 4
                hide = false
        strings:
                $0422_1 = "com/sun/jmx/mbeanserver/JmxMBeanServer" fullword
                $0422_2 = "com/sun/jmx/mbeanserver/JmxMBeanServerBuilder" fullword
                $0422_3 = "com/sun/jmx/mbeanserver/MBeanInstantiator" fullword
                $0422_4 = "findClass" fullword
                $0422_5 = "publicLookup" fullword
                $class = /sun\.org\.mozilla\.javascript\.internal\.(Context|GeneratedClassLoader)/ fullword 
        condition:
                (all of ($0422_*)) or (all of them)
}


/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule CVE_2015_1701_Taihou {
	meta:
		description = "CVE-2015-1701 compiled exploit code"
		author = "Florian Roth"
		reference = "http://goo.gl/W4nU0q"
		date = "2015-05-13"
		hash1 = "90d17ebd75ce7ff4f15b2df951572653efe2ea17"
		hash2 = "acf181d6c2c43356e92d4ee7592700fa01e30ffb"
		hash3 = "b8aabe12502f7d55ae332905acee80a10e3bc399"
		hash4 = "d9989a46d590ebc792f14aa6fec30560dfe931b1"
		hash5 = "63d1d33e7418daf200dc4660fc9a59492ddd50d9"
		score = 70
	strings:	
		$s3 = "VirtualProtect" fullword
		$s4 = "RegisterClass"
		$s5 = "LoadIcon"
		$s6 = "PsLookupProcessByProcessId" fullword ascii 
		$s7 = "LoadLibraryExA" fullword ascii
		$s8 = "gSharedInfo" fullword

		$w1 = "user32.dll" wide
		$w2 = "ntdll" wide	
	condition:
		uint16(0) == 0x5a4d and filesize < 160KB and all of ($s*) and 1 of ($w*)
}

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule Exploit_MS15_077_078: Exploit {
	meta:
		description = "MS15-078 / MS15-077 exploit - generic signature"
		author = "Florian Roth"
		reference = "https://code.google.com/p/google-security-research/issues/detail?id=473&can=1&start=200"
		date = "2015-07-21"
		hash1 = "18e3e840a5e5b75747d6b961fca66a670e3faef252aaa416a88488967b47ac1c"
		hash2 = "0b5dc030e73074b18b1959d1cf7177ff510dbc2a0ec2b8bb927936f59eb3d14d"
		hash3 = "fc609adef44b5c64de029b2b2cff22a6f36b6bdf9463c1bd320a522ed39de5d9"
		hash4 = "ad6bb982a1ecfe080baf0a2b27950f989c107949b1cf02b6e0907f1a568ece15"
	strings:
		$s1 = "GDI32.DLL" fullword ascii
		$s2 = "atmfd.dll" fullword wide
		$s3 = "AddFontMemResourceEx" fullword ascii
		$s4 = "NamedEscape" fullword ascii
		$s5 = "CreateBitmap" fullword ascii
		$s6 = "DeleteObject" fullword ascii

		$op0 = { 83 45 e8 01 eb 07 c7 45 e8 } /* Opcode */
		$op1 = { 8d 85 24 42 fb ff 89 04 24 e8 80 22 00 00 c7 45 } /* Opcode */
		$op2 = { eb 54 8b 15 6c 00 4c 00 8d 85 24 42 fb ff 89 44 } /* Opcode */
		$op3 = { 64 00 88 ff 84 03 70 03 }
	condition:
		uint16(0) == 0x5a4d and filesize < 2000KB and all of ($s*) or all of ($op*)
}

rule Exploit_MS15_077_078_HackingTeam: Exploit {
	meta:
		description = "MS15-078 / MS15-077 exploit - Hacking Team code"
		author = "Florian Roth"
		date = "2015-07-21"
		super_rule = 1
		hash1 = "ad6bb982a1ecfe080baf0a2b27950f989c107949b1cf02b6e0907f1a568ece15"
		hash2 = "fc609adef44b5c64de029b2b2cff22a6f36b6bdf9463c1bd320a522ed39de5d9"
	strings:
		$s1 = "\\SystemRoot\\system32\\CI.dll" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "\\sysnative\\CI.dll" fullword ascii /* PEStudio Blacklist: strings */
		$s3 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.125 Safari/537.36" fullword ascii /* PEStudio Blacklist: strings */
		$s4 = "CRTDLL.DLL" fullword ascii
		$s5 = "\\sysnative" fullword ascii /* PEStudio Blacklist: strings */
		$s6 = "InternetOpenA coolio, trying open %s" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 2500KB and all of them
}

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/


/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-05-25
	Identifier: Kaspersky Report on threats involving CVE-2015-2545
*/

/* Rule Set ----------------------------------------------------------------- */

rule Mal_Dropper_httpEXE_from_CAB : Dropper {
	meta:
		description = "Detects a dropper from a CAB file mentioned in the article"
		author = "Florian Roth"
		reference = "https://goo.gl/13Wgy1"
		date = "2016-05-25"
		score = 60
		hash1 = "9e7e5f70c4b32a4d5e8c798c26671843e76bb4bd5967056a822e982ed36e047b"
	strings:
		$s1 = "029.Hdl" fullword ascii
		$s2 = "http.exe" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 1000KB and ( all of ($s*) ) )
}

rule Mal_http_EXE : Trojan {
	meta:
		description = "Detects trojan from APT report named http.exe"
		author = "Florian Roth"
		reference = "https://goo.gl/13Wgy1"
		date = "2016-05-25"
		score = 80
		hash1 = "ad191d1d18841f0c5e48a5a1c9072709e2dd6359a6f6d427e0de59cfcd1d9666"
	strings:
		$x1 = "Content-Disposition: form-data; name=\"file1\"; filename=\"%s\"" fullword ascii
		$x2 = "%ALLUSERSPROFILE%\\Accessories\\wordpade.exe" fullword ascii
		$x3 = "\\dumps.dat" fullword ascii
		$x4 = "\\wordpade.exe" fullword ascii
		$x5 = "\\%s|%s|4|%d|%4d-%02d-%02d %02d:%02d:%02d|" fullword ascii
		$x6 = "\\%s|%s|5|%d|%4d-%02d-%02d %02d:%02d:%02d|" fullword ascii
		$x7 = "cKaNBh9fnmXgJcSBxx5nFS+8s7abcQ==" fullword ascii
		$x8 = "cKaNBhFLn1nXMcCR0RlbMQ==" fullword ascii /* base64: pKY1[1 */

		$s1 = "SELECT * FROM moz_logins;" fullword ascii
		$s2 = "makescr.dat" fullword ascii
		$s3 = "%s\\Mozilla\\Firefox\\profiles.ini" fullword ascii
		$s4 = "?moz-proxy://" fullword ascii
		$s5 = "[%s-%s] Title: %s" fullword ascii
		$s6 = "Cforeign key mismatch - \"%w\" referencing \"%w\"" fullword ascii
		$s7 = "Windows 95 SR2" fullword ascii
		$s8 = "\\|%s|0|0|" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 2000KB and ( 1 of ($x*) and 2 of ($s*) ) ) or ( 3 of ($x*) )
}

rule Mal_PotPlayer_DLL : dll {
	meta:
		description = "Detects a malicious PotPlayer.dll"
		author = "Florian Roth"
		reference = "https://goo.gl/13Wgy1"
		date = "2016-05-25"
		score = 70
		hash1 = "705409bc11fb45fa3c4e2fa9dd35af7d4613e52a713d9c6ea6bc4baff49aa74a"
	strings:
		$x1 = "C:\\Users\\john\\Desktop\\PotPlayer\\Release\\PotPlayer.pdb" fullword ascii

		$s3 = "PotPlayer.dll" fullword ascii
		$s4 = "\\update.dat" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 200KB and $x1 or all of ($s*)
}

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule Flash_CVE_2015_5119_APT3 : Exploit {
    meta:
        description = "Exploit Sample CVE-2015-5119"
        author = "Florian Roth"
        score = 70
        date = "2015-08-01"
    strings:
        $s0 = "HT_exploit" fullword ascii
        $s1 = "HT_Exploit" fullword ascii
        $s2 = "flash_exploit_" ascii
        $s3 = "exp1_fla/MainTimeline" ascii fullword
        $s4 = "exp2_fla/MainTimeline" ascii fullword
        $s5 = "_shellcode_32" fullword ascii
        $s6 = "todo: unknown 32-bit target" fullword ascii 
    condition:
        uint16(0) == 0x5746 and 1 of them
}

rule Linux_DirtyCow_Exploit {
   meta:
      description = "Detects Linux Dirty Cow Exploit - CVE-2012-0056 and CVE-2016-5195"
      author = "Florian Roth"
      reference = "http://dirtycow.ninja/"
      date = "2016-10-21"
   strings:
      $a1 = { 48 89 D6 41 B9 00 00 00 00 41 89 C0 B9 02 00 00 00 BA 01 00 00 00 BF 00 00 00 00 }

      $b1 = { E8 ?? FC FF FF 48 8B 45 E8 BE 00 00 00 00 48 89 C7 E8 ?? FC FF FF 48 8B 45 F0 BE 00 00 00 00 48 89 }
      $b2 = { E8 ?? FC FF FF B8 00 00 00 00 }

      $source1 = "madvise(map,100,MADV_DONTNEED);"
      $source2 = "=open(\"/proc/self/mem\",O_RDWR);"
      $source3 = ",map,SEEK_SET);"

      $source_printf1 = "mmap %x"
      $source_printf2 = "procselfmem %d"
      $source_printf3 = "madvise %d"
      $source_printf4 = "[-] failed to patch payload"
      $source_printf5 = "[-] failed to win race condition..."
      $source_printf6 = "[*] waiting for reverse connect shell..."

      $s1 = "/proc/self/mem"
      $s2 = "/proc/%d/mem"
      $s3 = "/proc/self/map"
      $s4 = "/proc/%d/map"

      $p1 = "pthread_create" fullword ascii
      $p2 = "pthread_join" fullword ascii
   condition:
      ( uint16(0) == 0x457f and $a1 ) or
      all of ($b*) or
      3 of ($source*) or
      ( uint16(0) == 0x457f and 1 of ($s*) and all of ($p*) and filesize < 20KB )
}

