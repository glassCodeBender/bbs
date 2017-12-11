/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule FE_LEGALSTRIKE_MACRO {
       meta:version=".1"
       filetype="MACRO"
       author="Ian.Ahl@fireeye.com @TekDefense"
       date="2017-06-02"
       description="This rule is designed to identify macros with the specific encoding used in the sample 30f149479c02b741e897cdb9ecd22da7."
strings:
       // OBSFUCATION
       $ob1 = "ChrW(114) & ChrW(101) & ChrW(103) & ChrW(115) & ChrW(118) & ChrW(114) & ChrW(51) & ChrW(50) & ChrW(46) & ChrW(101)" ascii wide
       $ob2 = "ChrW(120) & ChrW(101) & ChrW(32) & ChrW(47) & ChrW(115) & ChrW(32) & ChrW(47) & ChrW(110) & ChrW(32) & ChrW(47)" ascii wide
       $ob3 = "ChrW(117) & ChrW(32) & ChrW(47) & ChrW(105) & ChrW(58) & ChrW(104) & ChrW(116) & ChrW(116) & ChrW(112) & ChrW(115)" ascii wide
       $ob4 = "ChrW(58) & ChrW(47) & ChrW(47) & ChrW(108) & ChrW(121) & ChrW(110) & ChrW(99) & ChrW(100) & ChrW(105) & ChrW(115)" ascii wide
       $ob5 = "ChrW(99) & ChrW(111) & ChrW(118) & ChrW(101) & ChrW(114) & ChrW(46) & ChrW(50) & ChrW(98) & ChrW(117) & ChrW(110)" ascii wide
       $ob6 = "ChrW(110) & ChrW(121) & ChrW(46) & ChrW(99) & ChrW(111) & ChrW(109) & ChrW(47) & ChrW(65) & ChrW(117) & ChrW(116)" ascii wide
       $ob7 = "ChrW(111) & ChrW(100) & ChrW(105) & ChrW(115) & ChrW(99) & ChrW(111) & ChrW(118) & ChrW(101) & ChrW(114) & ChrW(32)" ascii wide
       $ob8 = "ChrW(115) & ChrW(99) & ChrW(114) & ChrW(111) & ChrW(98) & ChrW(106) & ChrW(46) & ChrW(100) & ChrW(108) & ChrW(108)" ascii wide
       $obreg1 = /(\w{5}\s&\s){7}\w{5}/
       $obreg2 = /(Chrw\(\d{1,3}\)\s&\s){7}/
       // wscript
       $wsobj1 = "Set Obj = CreateObject(\"WScript.Shell\")" ascii wide
       $wsobj2 = "Obj.Run " ascii wide

condition:
        (
              (
                      (uint16(0) != 0x5A4D)
              )
              and
              (
                      all of ($wsobj*) and 3 of ($ob*)
                      or
                      all of ($wsobj*) and all of ($obreg*)
              )
       )
}
rule FE_LEGALSTRIKE_MACRO_2 {
       meta:version=".1"
       filetype="MACRO"
       author="Ian.Ahl@fireeye.com @TekDefense"
       date="2017-06-02"
       description="This rule was written to hit on specific variables and powershell command fragments as seen in the macro found in the XLSX file3a1dca21bfe72368f2dd46eb4d9b48c4."
strings:
       // Setting the environment
       $env1 = "Arch = Environ(\"PROCESSOR_ARCHITECTURE\")" ascii wide
       $env2 = "windir = Environ(\"windir\")" ascii wide
       $env3 = "windir + \"\\syswow64\\windowspowershell\\v1.0\\powershell.exe\"" ascii wide
       // powershell command fragments
       $ps1 = "-NoP" ascii wide
       $ps2 = "-NonI" ascii wide
       $ps3 = "-W Hidden" ascii wide
       $ps4 = "-Command" ascii wide
       $ps5 = "New-Object IO.StreamReader" ascii wide
       $ps6 = "IO.Compression.DeflateStream" ascii wide
       $ps7 = "IO.MemoryStream" ascii wide
       $ps8 = ",$([Convert]::FromBase64String" ascii wide
       $ps9 = "ReadToEnd();" ascii wide
       $psregex1 = /\W\w+\s+\s\".+\"/
condition:
       (
              (
                      (uint16(0) != 0x5A4D)
              )
              and
              (
                      all of ($env*) and 6 of ($ps*)
                      or
                      all of ($env*) and 4 of ($ps*) and all of ($psregex*)
              )
       )
}
rule FE_LEGALSTRIKE_RTF {
    meta:
        version=".1"
        filetype="MACRO"
        author="joshua.kim@FireEye.com"
        date="2017-06-02"
        description="Rtf Phishing Campaign leveraging the CVE 2017-0199 exploit, to point to the domain 2bunnyDOTcom"

    strings:
        $header = "{\\rt"

        $lnkinfo = "4c0069006e006b0049006e0066006f"

        $encoded1 = "4f4c45324c696e6b"
        $encoded2 = "52006f006f007400200045006e007400720079"
        $encoded3 = "4f0062006a0049006e0066006f"
        $encoded4 = "4f006c0065"

        $http1 = "68{"
        $http2 = "74{"
        $http3 = "07{"

        // 2bunny.com
        $domain1 = "32{\\"
        $domain2 = "62{\\"
        $domain3 = "75{\\"
        $domain4 = "6e{\\"
        $domain5 = "79{\\"
        $domain6 = "2e{\\"
        $domain7 = "63{\\"
        $domain8 = "6f{\\"
        $domain9 = "6d{\\"

        $datastore = "\\*\\datastore"

    condition:
        $header at 0 and all of them
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule APT_OLE_JSRat : maldoc APT
{
meta:
	author = "Rahul Mohandas"
	Date = "2015-06-16"
	Description = "Targeted attack using Excel/word documents"
strings:
	$header = {D0 CF 11 E0 A1 B1 1A E1}
	$key1 = "AAAAAAAAAA"
	$key2 = "Base64Str" nocase
	$key3 = "DeleteFile" nocase
	$key4 = "Scripting.FileSystemObject" nocase
condition:
	$header at 0 and (all of ($key*) )
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule rtf_objdata_urlmoniker_http {
meta:
	ref = "https://blog.nviso.be/2017/04/12/analysis-of-a-cve-2017-0199-malicious-rtf-document/"
 strings:
 $header = "{\\rtf1"
 $objdata = "objdata 0105000002000000" nocase
 $urlmoniker = "E0C9EA79F9BACE118C8200AA004BA90B" nocase
 $http = "68007400740070003a002f002f00" nocase
 condition:
 $header at 0 and $objdata and $urlmoniker and $http
 }
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-09-14
   Identifier: Detects malicious files in releation with CVE-2017-8759
   Reference: https://github.com/Voulnet/CVE-2017-8759-Exploit-sample
*/

private rule RTFFILE {
   meta:
      description = "Detects RTF files"
   condition:
      uint32be(0) == 0x7B5C7274
}

/* Rule Set ----------------------------------------------------------------- */

rule CVE_2017_8759_Mal_HTA {
   meta:
      description = "Detects malicious files related to CVE-2017-8759 - file cmd.hta"
      author = "Florian Roth"
      reference = "https://github.com/Voulnet/CVE-2017-8759-Exploit-sample"
      date = "2017-09-14"
      hash1 = "fee2ab286eb542c08fdfef29fabf7796a0a91083a0ee29ebae219168528294b5"
   strings:
      $x1 = "Error = Process.Create(\"powershell -nop cmd.exe /c" fullword ascii
   condition:
      ( uint16(0) == 0x683c and filesize < 1KB and all of them )
}

rule CVE_2017_8759_Mal_Doc {
   meta:
      description = "Detects malicious files related to CVE-2017-8759 - file Doc1.doc"
      author = "Florian Roth"
      reference = "https://github.com/Voulnet/CVE-2017-8759-Exploit-sample"
      date = "2017-09-14"
      hash1 = "6314c5696af4c4b24c3a92b0e92a064aaf04fd56673e830f4d339b8805cc9635"
   strings:
      $s1 = "soap:wsdl=http://" ascii wide nocase
      $s2 = "soap:wsdl=https://" ascii wide nocase

      $c1 = "Project.ThisDocument.AutoOpen" fullword wide
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 500KB and 2 of them )
}

rule CVE_2017_8759_SOAP_via_JS {
   meta:
      description = "Detects SOAP WDSL Download via JavaScript"
      author = "Florian Roth"
      reference = "https://twitter.com/buffaloverflow/status/907728364278087680"
      date = "2017-09-14"
      score = 60
   strings:
      $s1 = "GetObject(\"soap:wsdl=https://" ascii wide nocase
      $s2 = "GetObject(\"soap:wsdl=http://" ascii wide nocase
   condition:
      ( filesize < 3KB and 1 of them )
}

rule CVE_2017_8759_SOAP_Excel {
   meta:
      description = "Detects malicious files related to CVE-2017-8759"
      author = "Florian Roth"
      reference = "https://twitter.com/buffaloverflow/status/908455053345869825"
      date = "2017-09-15"
   strings:
      $s1 = "|'soap:wsdl=" ascii wide nocase
   condition:
      ( filesize < 300KB and 1 of them )
}

rule CVE_2017_8759_SOAP_txt {
   meta:
      description = "Detects malicious file in releation with CVE-2017-8759 - file exploit.txt"
      author = "Florian Roth"
      reference = "https://github.com/Voulnet/CVE-2017-8759-Exploit-sample"
      date = "2017-09-14"
      hash1 = "840ad14e29144be06722aff4cc04b377364eeed0a82b49cc30712823838e2444"
   strings:
      $s1 = /<soap:address location="http[s]?:\/\/[^"]{8,140}.hta"/ ascii wide
      $s2 = /<soap:address location="http[s]?:\/\/[^"]{8,140}mshta.exe"/ ascii wide
   condition:
      ( filesize < 200KB and 1 of them )
}

rule CVE_2017_8759_WSDL_in_RTF {
   meta:
      description = "Detects malicious RTF file related CVE-2017-8759"
      author = "Security Doggo @xdxdxdxdoa"
      reference = "https://twitter.com/xdxdxdxdoa/status/908665278199996416"
      date = "2017-09-15"
   strings:
      $doc = "d0cf11e0a1b11ae1"
      $obj = "\\objupdate"
      $wsdl = "7700730064006c003d00" nocase
      $http1 = "68007400740070003a002f002f00" nocase
      $http2 = "680074007400700073003a002f002f00" nocase
      $http3 = "6600740070003a002f002f00" nocase
   condition:
      RTFFILE and $obj and $doc and $wsdl and 1 of ($http*)
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

/*
  Version 0.0.1 2016/03/21
  Source code put in public domain by Didier Stevens, no Copyright
  https://DidierStevens.com
  Use at your own risk

  Shortcomings, or todo's ;-) :

  History:
    2016/03/21: start
*/

rule Contains_VBE_File : maldoc
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
        description = "Detect a VBE file inside a byte sequence"
        method = "Find string starting with #@~^ and ending with ^#~@"
    strings:
        $vbe = /#@~\^.+\^#~@/
    condition:
        $vbe
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule Dridex_Trojan_XML : maldoc {
	meta:
		description = "Dridex Malware in XML Document"
		author = "Florian Roth @4nc4p"
		reference = "https://threatpost.com/dridex-banking-trojan-spreading-via-macros-in-xml-files/111503"
		date = "2015/03/08"
		hash1 = "88d98e18ed996986d26ce4149ae9b2faee0bc082"
		hash2 = "3b2d59adadf5ff10829bb5c27961b22611676395"
		hash3 = "e528671b1b32b3fa2134a088bfab1ba46b468514"
		hash4 = "981369cd53c022b434ee6d380aa9884459b63350"
		hash5 = "96e1e7383457293a9b8f2c75270b58da0e630bea"
	strings:
		// can be ascii or wide formatted - therefore no restriction
		$c_xml      = "<?xml version="
		$c_word     = "<?mso-application progid=\"Word.Document\"?>"
		$c_macro    = "w:macrosPresent=\"yes\""
		$c_binary   = "<w:binData w:name="
		$c_0_chars  = "<o:Characters>0</o:Characters>"
		$c_1_line   = "<o:Lines>1</o:Lines>"
	condition:
		all of ($c*)
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2015-12-02
	Identifier: Phishing Gina Harrowell Dez 2015
*/

rule PHISH_02Dez2015_dropped_p0o6543f {
	meta:
		description = "Phishing Wave - file p0o6543f.exe"
		author = "Florian Roth"
		reference = "http://myonlinesecurity.co.uk/purchase-order-124658-gina-harrowell-clinimed-limited-word-doc-or-excel-xls-spreadsheet-malware/"
		date = "2015-12-02"
		hash = "db788d6d3a8ed1a6dc9626852587f475e7671e12fa9c9faa73b7277886f1e210"
	strings:
		$s1 = "netsh.exe" fullword wide
		$s2 = "routemon.exe" fullword wide
		$s3 = "script=" fullword wide /* Goodware String - occured 4 times */
		$s4 = "disconnect" fullword wide /* Goodware String - occured 14 times */
		$s5 = "GetClusterResourceTypeKey" fullword ascii /* Goodware String - occured 17 times */
		$s6 = "QueryInformationJobObject" fullword ascii /* Goodware String - occured 34 times */
		$s7 = "interface" fullword wide /* Goodware String - occured 52 times */
		$s8 = "connect" fullword wide /* Goodware String - occured 61 times */
		$s9 = "FreeConsole" fullword ascii /* Goodware String - occured 91 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 250KB and all of them
}

rule PHISH_02Dez2015_attach_P_ORD_C_10156_124658 {
	meta:
		description = "Phishing Wave - file P-ORD-C-10156-124658.xls"
		author = "Florian Roth"
		reference = "http://myonlinesecurity.co.uk/purchase-order-124658-gina-harrowell-clinimed-limited-word-doc-or-excel-xls-spreadsheet-malware/"
		date = "2015-12-02"
		hash = "bc252ede5302240c2fef8bc0291ad5a227906b4e70929a737792e935a5fee209"
	strings:
		$s1 = "Execute" ascii
		$s2 = "Process WriteParameterFiles" fullword ascii
		$s3 = "WScript.Shell" fullword ascii
		$s4 = "STOCKMASTER" fullword ascii
		$s5 = "InsertEmailFax" ascii
	condition:
		uint16(0) == 0xcfd0 and filesize < 200KB and all of them
}

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule Contains_hidden_PE_File_inside_a_sequence_of_numbers : maldoc
{
	meta:
		author = "Martin Willing (https://evild3ad.com)"
		description = "Detect a hidden PE file inside a sequence of numbers (comma separated)"
		reference = "http://blog.didierstevens.com/2016/01/07/blackenergy-xls-dropper/"
		reference = "http://www.welivesecurity.com/2016/01/04/blackenergy-trojan-strikes-again-attacks-ukrainian-electric-power-industry/"
		date = "2016-01-09"
		filetype = "decompressed VBA macro code"
		
	strings:
		$a = "= Array(" // Array of bytes
		$b = "77, 90," // MZ
		$c = "33, 84, 104, 105, 115, 32, 112, 114, 111, 103, 114, 97, 109, 32, 99, 97, 110, 110, 111, 116, 32, 98, 101, 32, 114, 117, 110, 32, 105, 110, 32, 68, 79, 83, 32, 109, 111, 100, 101, 46," // !This program cannot be run in DOS mode.
	
	condition:
	 	all of them
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule MIME_MSO_ActiveMime_base64 : maldoc
{
	meta:
		author = "Martin Willing (https://evild3ad.com)"
		description = "Detect MIME MSO Base64 encoded ActiveMime file"
		date = "2016-02-28"
		filetype = "Office documents"
		
	strings:
		$mime = "MIME-Version:"
		$base64 = "Content-Transfer-Encoding: base64"
		$mso = "Content-Type: application/x-mso"
		$activemime = /Q(\x0D\x0A|)W(\x0D\x0A|)N(\x0D\x0A|)0(\x0D\x0A|)a(\x0D\x0A|)X(\x0D\x0A|)Z(\x0D\x0A|)l(\x0D\x0A|)T(\x0D\x0A|)W/
	
	condition:
		$mime at 0 and $base64 and $mso and $activemime
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule malicious_author : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 5
		
	strings:
		$magic = { 25 50 44 46 }
		
		$reg0 = /Creator.?\(yen vaw\)/
		$reg1 = /Title.?\(who cis\)/
		$reg2 = /Author.?\(ser pes\)/
	condition:
		$magic in (0..1024) and all of ($reg*)
}

rule suspicious_version : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 3
		
	strings:
		$magic = { 25 50 44 46 }
		$ver = /%PDF-1.\d{1}/
	condition:
		$magic in (0..1024) and not $ver
}

rule suspicious_creation : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 2
		
	strings:
		$magic = { 25 50 44 46 }
		$header = /%PDF-1\.(3|4|6)/
		
		$create0 = /CreationDate \(D:20101015142358\)/
		$create1 = /CreationDate \(2008312053854\)/
	condition:
		$magic in (0..1024) and $header and 1 of ($create*)
}

rule multiple_filtering : PDF raw
{
meta: 
author = "Glenn Edwards (@hiddenillusion)"
version = "0.2"
weight = 3

    strings:
            $magic = { 25 50 44 46 }
            $attrib = /\/Filter.*(\/ASCIIHexDecode\W+|\/LZWDecode\W+|\/ASCII85Decode\W+|\/FlateDecode\W+|\/RunLengthDecode){2}/ 
            // left out: /CCITTFaxDecode, JBIG2Decode, DCTDecode, JPXDecode, Crypt

    condition: 
            $magic in (0..1024) and $attrib
}

rule suspicious_title : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 4
		
	strings:
		$magic = { 25 50 44 46 }
		$header = /%PDF-1\.(3|4|6)/
		
		$title0 = "who cis"
		$title1 = "P66N7FF"
		$title2 = "Fohcirya"
	condition:
		$magic in (0..1024) and $header and 1 of ($title*)
}

rule suspicious_author : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 4
		
	strings:
		$magic = { 25 50 44 46 }
		$header = /%PDF-1\.(3|4|6)/

		$author0 = "Ubzg1QUbzuzgUbRjvcUb14RjUb1"
		$author1 = "ser pes"
		$author2 = "Miekiemoes"
		$author3 = "Nsarkolke"
	condition:
		$magic in (0..1024) and $header and 1 of ($author*)
}

rule suspicious_producer : PDF raw 
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 2
		
	strings:
		$magic = { 25 50 44 46 }
		$header = /%PDF-1\.(3|4|6)/
		
		$producer0 = /Producer \(Scribus PDF Library/
		$producer1 = "Notepad"
	condition:
		$magic in (0..1024) and $header and 1 of ($producer*)
}

rule suspicious_creator : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 3
		
	strings:
		$magic = { 25 50 44 46 }
		$header = /%PDF-1\.(3|4|6)/
		
		$creator0 = "yen vaw"
		$creator1 = "Scribus"
		$creator2 = "Viraciregavi"
	condition:
		$magic in (0..1024) and $header and 1 of ($creator*)
}

rule possible_exploit : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 3
		
	strings:
		$magic = { 25 50 44 46 }
		
		$attrib0 = /\/JavaScript /
		$attrib3 = /\/ASCIIHexDecode/
		$attrib4 = /\/ASCII85Decode/

		$action0 = /\/Action/
		$action1 = "Array"
		$shell = "A"
		$cond0 = "unescape"
		$cond1 = "String.fromCharCode"
		
		$nop = "%u9090%u9090"
	condition:
		$magic in (0..1024) and (2 of ($attrib*)) or ($action0 and #shell > 10 and 1 of ($cond*)) or ($action1 and $cond0 and $nop)
}

rule shellcode_blob_metadata : PDF raw
{
        meta:
                author = "Glenn Edwards (@hiddenillusion)"
                version = "0.1"
                description = "When there's a large Base64 blob inserted into metadata fields it often indicates shellcode to later be decoded"
                weight = 4
        strings:
                $magic = { 25 50 44 46 }

                $reg_keyword = /\/Keywords.?\(([a-zA-Z0-9]{200,})/ //~6k was observed in BHEHv2 PDF exploits holding the shellcode
                $reg_author = /\/Author.?\(([a-zA-Z0-9]{200,})/
                $reg_title = /\/Title.?\(([a-zA-Z0-9]{200,})/
                $reg_producer = /\/Producer.?\(([a-zA-Z0-9]{200,})/
                $reg_creator = /\/Creator.?\(([a-zA-Z0-9]{300,})/
                $reg_create = /\/CreationDate.?\(([a-zA-Z0-9]{200,})/

        condition:
                $magic in (0..1024) and 1 of ($reg*)
}

rule suspicious_js : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 3
		
	strings:
		$magic = { 25 50 44 46 }
		
		$attrib0 = /\/OpenAction /
		$attrib1 = /\/JavaScript /

		$js0 = "eval"
		$js1 = "Array"
		$js2 = "String.fromCharCode"
		
	condition:
		$magic in (0..1024) and all of ($attrib*) and 2 of ($js*)
}

rule suspicious_launch_action : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 2
		
	strings:
		$magic = { 25 50 44 46 }
		
		$attrib0 = /\/Launch/
		$attrib1 = /\/URL /
		$attrib2 = /\/Action/
		$attrib3 = /\/OpenAction/
		$attrib4 = /\/F /

	condition:
		$magic in (0..1024) and 3 of ($attrib*)
}

rule suspicious_embed : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		ref = "https://feliam.wordpress.com/2010/01/13/generic-pdf-exploit-hider-embedpdf-py-and-goodbye-av-detection-012010/"
		weight = 2
		
	strings:
		$magic = { 25 50 44 46 }
		
		$meth0 = /\/Launch/
		$meth1 = /\/GoTo(E|R)/ //means go to embedded or remote
		$attrib0 = /\/URL /
		$attrib1 = /\/Action/
		$attrib2 = /\/Filespec/
		
	condition:
		$magic in (0..1024) and 1 of ($meth*) and 2 of ($attrib*)
}

rule suspicious_obfuscation : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 2
		
	strings:
		$magic = { 25 50 44 46 }
		$reg = /\/\w#[a-zA-Z0-9]{2}#[a-zA-Z0-9]{2}/
		
	condition:
		$magic in (0..1024) and #reg > 5
}

rule invalid_XObject_js : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		description = "XObject's require v1.4+"
		ref = "https://blogs.adobe.com/ReferenceXObjects/"
		version = "0.1"
		weight = 2
		
	strings:
		$magic = { 25 50 44 46 }
		$ver = /%PDF-1\.[4-9]/
		
		$attrib0 = /\/XObject/
		$attrib1 = /\/JavaScript/
		
	condition:
		$magic in (0..1024) and not $ver and all of ($attrib*)
}

rule invalid_trailer_structure : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 1
		
        strings:
                $magic = { 25 50 44 46 }
				// Required for a valid PDF
                $reg0 = /trailer\r?\n?.*\/Size.*\r?\n?\.*/
                $reg1 = /\/Root.*\r?\n?.*startxref\r?\n?.*\r?\n?%%EOF/

        condition:
                $magic in (0..1024) and not $reg0 and not $reg1
}

rule multiple_versions : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
        description = "Written very generically and doesn't hold any weight - just something that might be useful to know about to help show incremental updates to the file being analyzed"		
		weight = 0
		
        strings:
                $magic = { 25 50 44 46 }
                $s0 = "trailer"
                $s1 = "%%EOF"

        condition:
                $magic in (0..1024) and #s0 > 1 and #s1 > 1
}

rule js_wrong_version : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		description = "JavaScript was introduced in v1.3"
		ref = "http://wwwimages.adobe.com/www.adobe.com/content/dam/Adobe/en/devnet/pdf/pdfs/pdf_reference_1-7.pdf"
		version = "0.1"
		weight = 2
		
        strings:
                $magic = { 25 50 44 46 }
				$js = /\/JavaScript/
				$ver = /%PDF-1\.[3-9]/

        condition:
                $magic in (0..1024) and $js and not $ver
}

rule JBIG2_wrong_version : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		description = "JBIG2 was introduced in v1.4"
		ref = "http://wwwimages.adobe.com/www.adobe.com/content/dam/Adobe/en/devnet/pdf/pdfs/pdf_reference_1-7.pdf"
		version = "0.1"
		weight = 1
		
        strings:
                $magic = { 25 50 44 46 }
				$js = /\/JBIG2Decode/
				$ver = /%PDF-1\.[4-9]/

        condition:
                $magic in (0..1024) and $js and not $ver
}

rule FlateDecode_wrong_version : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		description = "Flate was introduced in v1.2"
		ref = "http://wwwimages.adobe.com/www.adobe.com/content/dam/Adobe/en/devnet/pdf/pdfs/pdf_reference_1-7.pdf"
		version = "0.1"
		weight = 1
		
        strings:
                $magic = { 25 50 44 46 }
				$js = /\/FlateDecode/
				$ver = /%PDF-1\.[2-9]/

        condition:
                $magic in (0..1024) and $js and not $ver
}

rule embed_wrong_version : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		description = "EmbeddedFiles were introduced in v1.3"
		ref = "http://wwwimages.adobe.com/www.adobe.com/content/dam/Adobe/en/devnet/pdf/pdfs/pdf_reference_1-7.pdf"
		version = "0.1"
		weight = 1
		
        strings:
                $magic = { 25 50 44 46 }
				$embed = /\/EmbeddedFiles/
				$ver = /%PDF-1\.[3-9]/

        condition:
                $magic in (0..1024) and $embed and not $ver
}

rule invalid_xref_numbers : PDF raw
{
        meta:
			author = "Glenn Edwards (@hiddenillusion)"
			version = "0.1"
			description = "The first entry in a cross-reference table is always free and has a generation number of 65,535"
			notes = "This can be also be in a stream..."
			weight = 1
		
        strings:
                $magic = { 25 50 44 46 }
                $reg0 = /xref\r?\n?.*\r?\n?.*65535\sf/
                $reg1 = /endstream.*\r?\n?endobj.*\r?\n?startxref/
        condition:
                $magic in (0..1024) and not $reg0 and not $reg1
}

rule js_splitting : PDF raw
{
        meta:
                author = "Glenn Edwards (@hiddenillusion)"
                version = "0.1"
                description = "These are commonly used to split up JS code"
                weight = 2
                
        strings:
                $magic = { 25 50 44 46 }
				$js = /\/JavaScript/
                $s0 = "getAnnots"
                $s1 = "getPageNumWords"
                $s2 = "getPageNthWord"
                $s3 = "this.info"
                                
        condition:
                $magic in (0..1024) and $js and 1 of ($s*)
}

rule header_evasion : PDF raw
{
        meta:
                author = "Glenn Edwards (@hiddenillusion)"
                description = "3.4.1, 'File Header' of Appendix H states that ' Acrobat viewers require only that the header appear somewhere within the first 1024 bytes of the file.'  Therefore, if you see this trigger then any other rule looking to match the magic at 0 won't be applicable"
                ref = "http://wwwimages.adobe.com/www.adobe.com/content/dam/Adobe/en/devnet/pdf/pdfs/pdf_reference_1-7.pdf"
                version = "0.1"
                weight = 3

        strings:
                $magic = { 25 50 44 46 }
        condition:
                $magic in (5..1024) and #magic == 1
}

rule BlackHole_v2 : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		ref = "http://fortknoxnetworks.blogspot.no/2012/10/blackhhole-exploit-kit-v-20-url-pattern.html"
		weight = 3
		
	strings:
		$magic = { 25 50 44 46 }
		$content = "Index[5 1 7 1 9 4 23 4 50"
		
	condition:
		$magic in (0..1024) and $content
}


rule XDP_embedded_PDF : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		ref = "http://blog.9bplus.com/av-bypass-for-malicious-pdfs-using-xdp"
        weight = 1		

	strings:
		$s1 = "<pdf xmlns="
		$s2 = "<chunk>"
		$s3 = "</pdf>"
		$header0 = "%PDF"
		$header1 = "JVBERi0"

	condition:
		all of ($s*) and 1 of ($header*)
}

rule PDF_Embedded_Exe : PDF
{
	meta:
		ref = "https://github.com/jacobsoo/Yara-Rules/blob/master/PDF_Embedded_Exe.yar"
	strings:
    	$header = {25 50 44 46}
    	$Launch_Action = {3C 3C 2F 53 2F 4C 61 75 6E 63 68 2F 54 79 70 65 2F 41 63 74 69 6F 6E 2F 57 69 6E 3C 3C 2F 46}
        $exe = {3C 3C 2F 45 6D 62 65 64 64 65 64 46 69 6C 65 73}
    condition:
    	$header at 0 and $Launch_Action and $exe
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule ppaction {

meta:
	ref = "https://blog.nviso.be/2017/06/07/malicious-powerpoint-documents-abusing-mouse-over-actions/amp/"
	Description = "Malicious PowerPoint Documents Abusing Mouse Over Actions"
  hash = "68fa24c0e00ff5bc1e90c96e1643d620d0c4cda80d9e3ebeb5455d734dc29e7"

strings:
$a = "ppaction" nocase
condition:
$a
}

rule powershell {
strings:
$a = "powershell" nocase
condition:
$a
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/


rule Contains_UserForm_Object
{
	meta:
		author = "Martin Willing (https://evild3ad.com)"
		description = "Detect UserForm object in MS Office document"
		reference = "https://msdn.microsoft.com/en-us/library/office/gg264663.aspx"
		date = "2016-03-05"
		filetype = "Office documents"
		
	strings:
		$a = "UserForm1"
		$b = "TextBox1"
		$c = "Microsoft Forms 2.0"
	
	condition:
	 	all of them
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/


rule Contains_VBA_macro_code
{
	meta:
		author = "evild3ad"
		description = "Detect a MS Office document with embedded VBA macro code"
		date = "2016-01-09"
		filetype = "Office documents"

	strings:
		$officemagic = { D0 CF 11 E0 A1 B1 1A E1 }
		$zipmagic = "PK"

		$97str1 = "_VBA_PROJECT_CUR" wide
		$97str2 = "VBAProject"
		$97str3 = { 41 74 74 72 69 62 75 74 00 65 20 56 42 5F } // Attribute VB_

		$xmlstr1 = "vbaProject.bin"
		$xmlstr2 = "vbaData.xml"

	condition:
		($officemagic at 0 and any of ($97str*)) or ($zipmagic at 0 and any of ($xmlstr*))
}
rule hancitor_dropper : vb_win32api
{
  meta:
    author = "Jeff White - jwhite@paloaltonetworks @noottrak"
    date   = "18AUG2016"
    hash1  = "03aef51be133425a0e5978ab2529890854ecf1b98a7cf8289c142a62de7acd1a"
    hash2  = "4b3912077ef47515b2b74bc1f39de44ddd683a3a79f45c93777e49245f0e9848"
    hash3  = "a78972ac6dee8c7292ae06783cfa1f918bacfe956595d30a0a8d99858ce94b5a"

  strings:
    $api_01 = { 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 }  // VirtualAlloc
    $api_02 = { 00 52 74 6C 4D 6F 76 65 4D 65 6D 6F 72 79 00 }  // RtlMoveMemory
    $api_04 = { 00 43 61 6C 6C 57 69 6E 64 6F 77 50 72 6F 63 41 00 }  // CallWindowProcAi
    $magic  = { 50 4F 4C 41 }  // POLA

  condition:
    uint32be(0) == 0xD0CF11E0 and all of ($api_*) and $magic
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule malrtf_ole2link : exploit
{
	meta:
		author = "@h3x2b <tracker _AT h3x.eu>"
		description = "Detect weaponized RTF documents with OLE2Link exploit"

	strings:
		//normal rtf beginning
		$rtf_format_00 = "{\\rtf1"
		//malformed rtf can have for example {\\rtA1
		$rtf_format_01 = "{\\rt"

		//having objdata structure
		$rtf_olelink_01 = "\\objdata" nocase

		//hex encoded OLE2Link
		$rtf_olelink_02 = "4f4c45324c696e6b" nocase

		//hex encoded docfile magic - doc file albilae
		$rtf_olelink_03 = "d0cf11e0a1b11ae1" nocase

		//hex encoded "http://"
		$rtf_payload_01 = "68007400740070003a002f002f00" nocase

		//hex encoded "https://"
		$rtf_payload_02 = "680074007400700073003a002f002f00" nocase

		//hex encoded "ftp://"
		$rtf_payload_03 = "6600740070003a002f002f00" nocase


	condition:
		//new_file and
		any of ($rtf_format_*)
		and all of ($rtf_olelink_*)
		and any of ($rtf_payload_*)
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule maldoc_API_hashing : maldoc
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a1 = {AC 84 C0 74 07 C1 CF 0D 01 C7 EB F4 81 FF}
        $a2 = {AC 84 C0 74 07 C1 CF 07 01 C7 EB F4 81 FF}
    condition:
        any of them
}

// 20150909 - Issue #39 - Commented because of High FP rate
/*
rule maldoc_function_prolog_signature : maldoc
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a1 = {55 8B EC 81 EC}
        $a2 = {55 8B EC 83 C4}
        $a3 = {55 8B EC E8}
        $a4 = {55 8B EC E9}
        $a5 = {55 8B EC EB}
    condition:
        any of them
}
*/

// 20150909 - Issue #39 - Commented because of High FP rate
/*
rule maldoc_structured_exception_handling : maldoc
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a1 = {64 8B (05|0D|15|1D|25|2D|35|3D) 00 00 00 00}
        $a2 = {64 A1 00 00 00 00}
    condition:
        any of them
}
*/

rule maldoc_indirect_function_call_1 : maldoc
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a = {FF 75 ?? FF 55 ??}
    condition:
        for any i in (1..#a): (uint8(@a[i] + 2) == uint8(@a[i] + 5))
}

rule maldoc_indirect_function_call_2 : maldoc
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a = {FF B5 ?? ?? ?? ?? FF 95 ?? ?? ?? ??}
    condition:
        for any i in (1..#a): ((uint8(@a[i] + 2) == uint8(@a[i] + 8)) and (uint8(@a[i] + 3) == uint8(@a[i] + 9)) and (uint8(@a[i] + 4) == uint8(@a[i] + 10)) and (uint8(@a[i] + 5) == uint8(@a[i] + 11)))
}

rule maldoc_indirect_function_call_3 : maldoc
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a = {FF B7 ?? ?? ?? ?? FF 57 ??}
    condition:
        $a
}

rule maldoc_find_kernel32_base_method_1 : maldoc
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a1 = {64 8B (05|0D|15|1D|25|2D|35|3D) 30 00 00 00}
        $a2 = {64 A1 30 00 00 00}
    condition:
        any of them
}

rule maldoc_find_kernel32_base_method_2 : maldoc
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a = {31 ?? ?? 30 64 8B ??}
    condition:
        for any i in (1..#a): ((uint8(@a[i] + 1) >= 0xC0) and (((uint8(@a[i] + 1) & 0x38) >> 3) == (uint8(@a[i] + 1) & 0x07)) and ((uint8(@a[i] + 2) & 0xF8) == 0xA0) and (uint8(@a[i] + 6) <= 0x3F) and (((uint8(@a[i] + 6) & 0x38) >> 3) != (uint8(@a[i] + 6) & 0x07)))
}

rule maldoc_find_kernel32_base_method_3 : maldoc
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a = {68 30 00 00 00 (58|59|5A|5B|5C|5D|5E|5F) 64 8B ??}
    condition:
        for any i in (1..#a): (((uint8(@a[i] + 5) & 0x07) == (uint8(@a[i] + 8) & 0x07)) and (uint8(@a[i] + 8) <= 0x3F) and (((uint8(@a[i] + 8) & 0x38) >> 3) != (uint8(@a[i] + 8) & 0x07)))
}

rule maldoc_getEIP_method_1 : maldoc
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a = {E8 00 00 00 00 (58|59|5A|5B|5C|5D|5E|5F)}
    condition:
        $a
}

rule maldoc_getEIP_method_4 : maldoc
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a1 = {D9 EE D9 74 24 F4 (58|59|5A|5B|5C|5D|5E|5F)}
        $a2 = {D9 EE 9B D9 74 24 F4 (58|59|5A|5B|5C|5D|5E|5F)}
    condition:
        any of them
}

// 20150909 - Issue #39 - Commented because of High FP rate
/*
rule maldoc_suspicious_strings : maldoc
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a01 = "CloseHandle"
        $a02 = "CreateFile"
        $a03 = "GetProcAddr"
        $a04 = "GetSystemDirectory"
        $a05 = "GetTempPath"
        $a06 = "GetWindowsDirectory"
        $a07 = "IsBadReadPtr"
        $a08 = "IsBadWritePtr"
        $a09 = "LoadLibrary"
        $a10 = "ReadFile"
        $a11 = "SetFilePointer"
        $a12 = "ShellExecute"
        $a13 = "UrlDownloadToFile"
        $a14 = "VirtualAlloc"
        $a15 = "WinExec"
        $a16 = "WriteFile"
    condition:
        any of them
}
*/

rule mwi_document: exploitdoc maldoc
{
    meta:
        description = "MWI generated document"
        author = "@Ydklijnsma"
        source = "http://blog.0x3a.com/post/117760824504/analysis-of-a-microsoft-word-intruder-sample"

      strings:
        $field_creation_tag = "{\\field{\\*\\fldinst { INCLUDEPICTURE"
        $mwistat_url = ".php?id="
        $field_closing_tag = "\\\\* MERGEFORMAT \\\\d}}{\\fldrslt}}"

    condition:
        all of them
}

rule macrocheck : maldoc
{
    meta:
        Author      = "Fireeye Labs"
        Date        = "2014/11/30" 
        Description = "Identify office documents with the MACROCHECK credential stealer in them.  It can be run against .doc files or VBA macros extraced from .docx files (vbaProject.bin files)."
        Reference   = "https://www.fireeye.com/blog/threat-research/2014/11/fin4_stealing_insid.html"

    strings:
        $PARAMpword = "pword=" ascii wide
        $PARAMmsg = "msg=" ascii wide
        $PARAMuname = "uname=" ascii
        $userform = "UserForm" ascii wide
        $userloginform = "UserLoginForm" ascii wide
        $invalid = "Invalid username or password" ascii wide
        $up1 = "uploadPOST" ascii wide
        $up2 = "postUpload" ascii wide
 
    condition:
        all of ($PARAM*) or (($invalid or $userloginform or $userform) and ($up1 or $up2))
}
rule office_document_vba : maldoc
{
	meta:
		description = "Office document with embedded VBA"
		author = "Jean-Philippe Teissier / @Jipe_"
		date = "2013-12-17"
		reference = "https://github.com/jipegit/"

	strings:
		$officemagic = { D0 CF 11 E0 A1 B1 1A E1 }
		$zipmagic = "PK"

		$97str1 = "_VBA_PROJECT_CUR" wide
		$97str2 = "VBAProject"
		$97str3 = { 41 74 74 72 69 62 75 74 00 65 20 56 42 5F }

		$xmlstr1 = "vbaProject.bin"
		$xmlstr2 = "vbaData.xml"

	condition:
		($officemagic at 0 and any of ($97str*)) or ($zipmagic at 0 and any of ($xmlstr*))
}

rule Office_AutoOpen_Macro : maldoc {
	meta:
		description = "Detects an Microsoft Office file that contains the AutoOpen Macro function"
		author = "Florian Roth"
		date = "2015-05-28"
		score = 60
		hash1 = "4d00695d5011427efc33c9722c61ced2"
		hash2 = "63f6b20cb39630b13c14823874bd3743"
		hash3 = "66e67c2d84af85a569a04042141164e6"
		hash4 = "a3035716fe9173703941876c2bde9d98"
		hash5 = "7c06cab49b9332962625b16f15708345"
		hash6 = "bfc30332b7b91572bfe712b656ea8a0c"
		hash7 = "25285b8fe2c41bd54079c92c1b761381"
	strings:
		$s1 = "AutoOpen" ascii fullword
		$s2 = "Macros" wide fullword
	condition:
		uint32be(0) == 0xd0cf11e0 and all of ($s*) and filesize < 300000
}

rule Embedded_EXE_Cloaking : maldoc {
    meta:
        description = "Detects an embedded executable in a non-executable file"
        author = "Florian Roth"
        date = "2015/02/27"
        score = 80
    strings:
        $noex_png = { 89 50 4E 47 }
        $noex_pdf = { 25 50 44 46 }
        $noex_rtf = { 7B 5C 72 74 66 31 }
        $noex_jpg = { FF D8 FF E0 }
        $noex_gif = { 47 49 46 38 }
        $mz  = { 4D 5A }
        $a1 = "This program cannot be run in DOS mode"
        $a2 = "This program must be run under Win32"       
    condition:
        (
            ( $noex_png at 0 ) or
            ( $noex_pdf at 0 ) or
            ( $noex_rtf at 0 ) or
            ( $noex_jpg at 0 ) or
            ( $noex_gif at 0 )
        )
        and
        for any i in (1..#mz): ( @a1 < ( @mz[i] + 200 ) or @a2 < ( @mz[i] + 200 ) )
}

// This rule have beed improved by Javier Rascon
rule RTF_Shellcode : maldoc
{
    meta:

        author = "RSA-IR – Jared Greenhill"
        date = "01/21/13"
        description = "identifies RTF's with potential shellcode"
            filetype = "RTF"

    strings:
        $rtfmagic={7B 5C 72 74 66}
        /* $scregex=/[39 30]{2,20}/ */
        $scregex=/(90){2,20}/

    condition:

        ($rtfmagic at 0) and ($scregex)
}
