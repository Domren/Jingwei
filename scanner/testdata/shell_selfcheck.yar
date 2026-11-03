rule Legacy_Shell_Credential_Leak
{
    meta:
        description = "Legacy encrypted shell sends the password next to the ciphertext"
        author = "jingwei selfcheck"
    strings:
        $pwd = "pwd="
        $enc = "enc="
    condition:
        any of them
}

rule Generic_Plaintext_Webshell
{
    meta:
        description = "Common plaintext PHP webshell primitives; v2 payloads must not combine them"
        author = "jingwei selfcheck"
    strings:
        $post = "$_POST"
        $request = "$_REQUEST"
        $system = "system("
        $passthru = "passthru("
    condition:
        2 of them
}
