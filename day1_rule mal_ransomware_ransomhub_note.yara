rule mal_ransomware_ransomhub_note
{
    meta:
        author = "manb4t"
        date = "2024/01/10" //UK Date Format
        ref = "https://github.com/m4nbat/100_days_of_yara_2025/tree/main"
        description = "string based detection for ransomhub ransomware note"
        note1_sha256 = "2b8e5ad115ebce0a9e65d734a2d198a49d2f3529eb68c65658a814b2a1ddbfa2"
        note2_sha256 = "1515a60da27560246d4334f867d2a311f0fc7435961cb6851e350c09b3645f39"
        note3_sha256 = "8b288e578801d6e2468d5cd0c47d40c3245cd2a79b0e99f91aee0b25b0fbad8c"
        note4_sha256 = "daefefbb08a9a2a6ce698b859bf7fe809eed24c671367ea613b1996298be6abb"
        
    strings:
        $string1 = "Your company Servers are locked and Data has been taken to our servers."
        $string2 = "All countries have their own PDPL (Personal Data Protection Law) regulations"
        $string3 = "Install and run 'Tor Browser' from https://www.torproject.org/download/"
        $string4 = "Tor Browser Links:"
        $string5 = "RansomHub" nocase
        $string6 = "https://en.wikipedia.org/wiki/General_Data_Protection_Regulation"
        $string7 = "nstall and run 'Tor Browser"
        $string8 = "- Go to http://"
        $string9 = "- Log in using the Client ID:"
        $string10 = "Just focus on negotiations, payment and decryption to make all of your problems solved by our specialists within 1 day after payment received:"
        $string11 = "Think your partner IT Recovery Company will do files restoration?"
        $string12 = "If you have an external or cloud backup; what happens if you don’t agree with us?"
        $string13 = "from https://www.torproject.org/download/"
	$url1 = "ransomxifxwc5eteopdobynonjctkxxvap77yqifu2emfbecgbqdw6qd.onion"
        // add additional url strings to match on as the otr site url changes in the future 
        
    condition:
        filesize < 10KB and
        6 of ($string1, $string2, $string3, $string4, $string5, $string6, $string8, $string9, $string10, $string11, $string12) and
        all of ($string7, $string13) and
        any of ($url*)
}
