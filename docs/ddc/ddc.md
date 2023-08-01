---
layout: default
title: "Digital Defenders Cybersecurity CTF 2023 | WriteUps"
has_children: true
nav_order: 2
permalink: /docs/ddc
---


# Digital Defenders Cybersecurity CTF 2023

{: .no_toc .text-delta }

# 1. Laughable File Infiltration 📂
{:toc}
---
#### #LFI #WEB 

Website:
![](../resources/ctf/lfi1/1.png)

On opening a page we can look at URL and determine that `view` page is loading files locally using value passed in GET parameter `file`. 
![](../resources/ctf/lfi1/2.png)

Testing **Local File Inclusion** by requesting `/etc/passwd` file.

![](../resources/ctf/lfi1/3.png)
We got the file. Now we can request for Flag.
![](../resources/ctf/lfi1/4.png)


<div style="page-break-after: always"></div>


# 2. CookieMonster 🍪
{:toc}
---

#### #Cookies #Base64 #CyberChef #WEB 

Website:
![](../resources/ctf/cookiemonster/1.png)

As name of this challenge is suggesting, looking the cookies.

![](../resources/ctf/cookiemonster/2.png)
I put the value of `cookie` in [CyberChef](https://cyberchef.org/) and after
- URL Decoding
- Base64 decoding

we can see it just a JSON value.
![](../resources/ctf/cookiemonster/3.png)

After modifying the admin value to 1 and encoding it back again. I submitted it in the browser and refreshed the page.
![](../resources/ctf/cookiemonster/4.png)

And we can see the FLAG.
![](../resources/ctf/cookiemonster/5.png)


<div style="page-break-after: always"></div>

# 3. Phone Book 📞
{:toc}

---
#### #IDOR #WEB 

Challenge webpage:
![](../resources/ctf/phonebook/1.png)

On clicking `Click Here` button we get a Name and Phone Number, but if you look at the URL, the user details which this page is displaying is associated with `id=1`.
![](../resources/ctf/phonebook/2.png)

On requesting `id=2`, we get some other user's details.
![](../resources/ctf/phonebook/3.png)

On requesting `id=0` we got the FLAG.
![](../resources/ctf/phonebook/4.png)


<div style="page-break-after: always"></div>

# 4. Secret keeper 🤐
{:toc}

---
#### #SQLi #WEB

Challenge Website:
![](../resources/ctf/sec_keeper/1.png)

Testing this payload and see is anything breaks or not. As if our username and password gets directly embeds into the SQL query it will produce some kind of error because of `'`(single quotation mark).
```text
username: admin'
password: anything
```

And it out breaks and produces errors which are directly shown on the webpage. From these errors we can get to know some insights about the backend. 
![](../resources/ctf/sec_keeper/2.png)

After some guessing about the query this payload worked and allowed us to bypass the login page and see our FLAG.

<div style="page-break-after: always"></div>

```text
username: admin' or '1'='1'-- -
password: anything
```

![](../resources/ctf/sec_keeper/3.png)


<div style="page-break-after: always"></div>

# 5. Shellshocker 🐚
{:toc}
---
#### #Linux #WEB


Challenge website:
![](../resources/ctf/shellshocker/1.png)

Executing commands and it runs properly.
![](../resources/ctf/shellshocker/2.png)

Finding flag file as it's path was not mentioned in challenge description.
```bash
$ find / -name *flag* -type f 2>/dev/null
```
This command will find any file which have name related to flag and any errors will be redirected to `/dev/null`.

We found two flag related files.
![](../resources/ctf/shellshocker/3.png)

using `cat` to read both files. Seems like one flag file was a decoy.
![](../resources/ctf/shellshocker/4.png)

<div style="page-break-after: always"></div>

# 6. Ghost 👻
{:toc}
---
#### #PHP #WebShell #WEB 

**Webpage**:
![](../resources/ctf/ghost/1.png)

We can upload our files and it will provide us the URL through which we can access our uploaded our file.
First thing I check was to upload a PHP Web-shell to test whether it have executable write our not.

I uploaded this [artyuum/simple-php-web-shell · GitHub](https://github.com/artyuum/simple-php-web-shell/blob/master/index.php)

And it worked !!.
![[../resources/ctf/ghost/2.png]]

We can easily run our commands and get the output.
![](../resources/ctf/ghost/3.png)

FLAG:
![](../resources/ctf/ghost/4.png)


<div style="page-break-after: always"></div>


# 7. Laughable File Infiltration 2 📂
{:toc}
---
#### #LFI #FilterBypass #WEB #Burp


**Website**:
![](../resources/ctf/lfi2/1.png)

Intercepting the request using Burp and we can see How a local file is loaded using POST parameter.
![](../resources/ctf/lfi2/2.png)

Requested for `/etc/passwd` file and we got it back.
![](../resources/ctf/lfi2/3.png)

On request for `flag.txt`, we are getting the response `.txt` not found ?!!.
![](../resources/ctf/lfi2/4.png)
There seems to be some kind of filtering which is removing `flag` word from the parameter data.
![](../resources/ctf/lfi2/5.png)
`flagflag` was also removed.
I am guessing filter goes in one pass and removes `flag` word. So we can bypass it if we pass `flflagag` after filtering it will become `flag` and we can access our FLAG.

![](../resources/ctf/lfi2/6.png)

It Worked !!!


<div style="page-break-after: always"></div>

# 8. XML Parser 📄
{:toc}
---
#### #WEB #XXE


Webpage ask to enter XML string for it to parse, first thing I do it test some payloads.
- [payloadbox/xxe-injection-payload-list: 🎯 XML External Entity (XXE) Injection Payload List](https://github.com/payloadbox/xxe-injection-payload-list)

**Payload 1**:
![](../resources/ctf/xml/1.png)

**Output 1**:
![](../resources/ctf/xml/2.png)

Now we can test some payloads to read some local files.

<div style="page-break-after: always"></div>

Payload:
```xml
<!--?xml version="1.0" ?-->
<!DOCTYPE replace [<!ENTITY ent SYSTEM "file:///etc/passwd"> ]>
<userInfo>
 <firstName>John</firstName>
 <lastName>&ent;</lastName>
</userInfo>
```

It printed `/etc/passwd` file.
![](../resources/ctf/xml/3.png)

Now we can replace path to `flag.txt` and read the FLAG.

![](../resources/ctf/xml/4.png)


<div style="page-break-after: always"></div>


# 9. Pr0j3ct M3t4 💻
{:toc}
---
#### #Forensics #MetaData #Base64 

Checking file type using `file` command it tells it's a JPEG image file and have a weird looking comment. From looks of it, seems Base64.

![](../resources/ctf/project/1.png)

We can also use `exiftool` to see some extra information as well.
![](../resources/ctf/project/1.1.png)

Decoding base64 comment and getting FLAG.
![](../resources/ctf/project/2.png)

<div style="page-break-after: always"></div>

# 10. R3c0v3rytxt 🔄
{:toc}
---
#### #Forensics #Volality3 #FileScan


For memory forensics I am using `Volality3`.

Firstly looking the information about the Image, we can tell this Image is of Windows 7 SP1, time of system and more.
![](../resources/ctf/recovery/1.png)

Since name of the challenge is Recovery Text, I will scan the image for available files, and find `flag` related named files. 
![](../resources/ctf/recovery/2.png)

There is our `flag.txt`. We can recover this file can read the contents of the file.
![](../resources/ctf/recovery/3.png)

<div style="page-break-after: always"></div>

# 11. brut3nf0rce 🔓
{:toc}
---
#### #Forensics #fcrackzip #Python3 #Bruteforce

In this challenge we are given a password protected ZIP file, which according to challenge  description has password of less then 3 characters. So we can make our own wordlist that contains combination of every printable characters and length less equal to 3.

For the wordlist I created a python code which will make all combinations and save them in a file.

```python
import itertools
import string

def generate_wordlist():
    wordlist = []

    # Generate one-character words
    for char in string.printable:
        wordlist.append(char)

    # Generate two-character words
    for chars in itertools.product(string.printable, repeat=2):
        wordlist.append(''.join(chars))

    # Generate three-character words
    for chars in itertools.product(string.printable, repeat=3):
        wordlist.append(''.join(chars))

    return wordlist

# Generate the wordlist
wordlist = generate_wordlist()

# Save the wordlist to a text file
filename = "wordlist.txt"
with open(filename, "w") as file:
    file.write("\n".join(wordlist))

print(f"Wordlist generated and saved in {filename}.")

```


**Brute forcing** the password for ZIP file using a tool called `fcrackzip`

![](../resources/ctf/brute/1.png)

And we found the password `gz`.

After extracting the ZIP file a `chall7.jpg` file is extracted. We can verify that it's a JPEG file using `file` command.

![](../resources/ctf/brute/2.png)

According to challenge description there has to be a secret file which we need to extract. So I ran a tool called `binwalk`, but it  found nothing.

![](../resources/ctf/brute/3.png)

There is another tool available `stegseek` which can be used to extract hidden data from file.

![](../resources/ctf/brute/4.png)
It found `secret.txt` and it contained our FLAG.

![](../resources/ctf/brute/5.png)

<div style="page-break-after: always"></div>


# 12. Common Primes 🔢
{:toc}
---
#### #Cryptography #RSA

Code provided shows how message was encrypted:
```python
from Crypto.Util.number import *

modulus_list = [<SNIP>..<SNIP>]
e = 65537
flag = b"flag{######################}"

message = bytes_to_long(flag)
ciphertext = [pow(message, e, modulus_list[i]) for i in range(4)]

obj1 = open("ciphertext.txt",'w')
obj1.write(str(ciphertext))
```

We can figure out by looking at the code that  flag has been encrypted using different modulus given in the list.

As the name of the challenge suggests common primes, the first idea is to check for any numbers that have common prime from the `modulus_list`.

![](../resources/ctf/prime/1.png)
And we found 2nd and 4th number from the list have common primes.
Let this common prime as $p$. 
now the $q$ will be $q = \frac{n}{p}$.
Since we have both $p$ and $q$, we can find $\phi$.
$$
\phi = (p-1)\times(q-1)
$$
Therefore our private key will be 
$$
d = e^{-1}\pmod \phi
$$
![](../resources/ctf/prime/2.png)

And finally we can easily decrypt our message using our private key and find the flag.

![](../resources/ctf/prime/3.png)

<div style="page-break-after: always"></div>

# 13. Wojtek's Enigma 🕵️‍♂️
{:toc}
---
#### #Cryptography #EnigmaDecoder


Challenge :

![](../resources/ctf/enigma/1.png)

flag is jumbled with all this mechanical specifications given. Searching about it a little found this website: [Enigma Machine | Cryptii ](https://cryptii.com/pipes/enigma-machine)

![](../resources/ctf/enigma/2.png)

Setting the machine according to given specifications and we found the flag.

<div style="page-break-after: always"></div>

# 14. MOD 🔐
{:toc}
---
#### #Cryptography #Encoding #Mod


Challenge code:
```python
flag = #######redacted#######
flag = flag.encode()
l = [i%97 for i in flag]

print(l)
```

Encode text:
```text
[5, 11, 0, 6, 26, 77, 48, 3, 20, 49, 48, 95, 12, 52, 10, 51, 18, 95, 55, 7, 8, 13, 6...
```

Looking at what code is doing:
```cmd
>>> a = 'abc'.encode()
>>> a[0]%97
0
>>> a[1]%97
1
>>> a[2]%97
2
>>> b = 'xyz'.encode()
>>> b[0]%97
23
>>> b[2]%97
25
```

Now we can easily think of a logic to convert back
```python
import string
enocde = [5, 11, 0, 6, 26, 77, 48, 3, 20, 49, 48, 95, 12, 52, 10, 51, 18, 95, 55, 7, 8, 13, 6, 18, 95, 11, 48, 48, 15,28]
final = ""
for x in enocde:
    if x > 28:
        final += str(chr(x))
    else:
        final += str(chr(x+97))
print(final)
```

![](../resources/ctf/mod/1.png)

<div style="page-break-after: always"></div>

# 15. Grandfather cipher 🧓🔑
{:toc}
---
#### #Cryptography #key


Challenge code:
```python
letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}'
key = "????"
flag = "????"

def encrypt(plaintext, key):
    
    plaintext = plaintext.upper()
    key = key.upper()
    char_to_val = {char:val for val,char in enumerate(letters)}
    ciphertext = ""

    for i, char in enumerate(plaintext):
        plaintext_val = char_to_val[char]
        key_val = char_to_val[key[i % len(key))
        cipher_val = (plaintext_val + key_val) % len(letters)
        cipher_char = letters[cipher_val]
        ciphertext += cipher_char

    return ciphertext

print(encrypt(flag,key))
```

Cipher text:
```
O8Q2HZE9PCID38QDRL3COL7C3ZS01DVEU8CX01Q6R{WDQ1}4P13001S4Y4UH6W
```

Since Key used in the above code is not provided so have to find a way to guess the key.
We know Cypher text and some part of plain text, basically First few part and last letter that is

```
FLAG{ ...... }
```

So we can brute force letters of key one by one to find which letter made the corresponding letter to plain text into cipher text.

like,
$(F + key_1) \xrightarrow{ALGO} O$
$(L + key_2) \xrightarrow{ALGO} 8$
$(A + key_3) \xrightarrow{ALGO} Q$
$(G + key_4) \xrightarrow{ALGO} 2$
$(\ \{ + key_5) \xrightarrow{ALGO} H$
$(\ \} + key_6) \xrightarrow{ALGO} W$

Python code to find the key:
```python
def find_key(plaintext, ciphertext):
    plaintext = plaintext.upper()
    ciphertext = ciphertext.upper()
    letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}'
    
    char_to_val = {char: val for val, char in enumerate(letters)}

    for key_val in range(len(letters)):
        key_char = letters[key_val]
        plaintext_val = char_to_val[plaintext]
        decrypted_val = (char_to_val[ciphertext] - key_val) % len(letters)
        
        if decrypted_val == plaintext_val:
            return key_char
    
    return None

wordlist = {
    'F':'O',
    'L':'8',
    'A':'Q',
    'G':'2',
    '{':'H',
    '}':'W'
}

for plain_char,cipher_char in wordlist.items():
    key_char = find_key(plain_char, cipher_char)
    print("The key used for encryption is:",key_char)
```

After running the code we find find is `JXQWJX`. I am assuming that key is short as `J` and `X` are repeating, therefore I am going with the key as `JXQW`.

![](../resources/ctf/grandfather/1.png)

To decrypt the Cypher text we simply have to do the reverse of the given function. Everything remains the same just change would be :
In Encrypting code we were getting `ciphertex_val` by adding `plaintext_val` and `key_val`, In decrypt code we have the `ciphertex_val` and `key_val`, so we will simply subtract `key_val` from  `ciphertex_val` to get `plaintext_val`.

```python
def decrypt(ciphertext, key):
    ciphertext = ciphertext.upper()
    key = key.upper()
    letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}'
    
    char_to_val = {char: val for val, char in enumerate(letters)}
    plaintext = ""
    
    for i, char in enumerate(ciphertext):
        ciphertext_val = char_to_val[char]
        key_val = char_to_val[key[i % len(key))
        plaintext_val = (ciphertext_val - key_val) % len(letters)
        plaintext_char = letters[plaintext_val]
        plaintext += plaintext_char
    
    return plaintext

ciphertext = 'O8Q2HZE9PCID38QDRL3COL7C3ZS01DVEU8CX01Q6R{WDQ1}4P13001S4Y4UH6W'
key = 'JXQW'
plaintext = decrypt(ciphertext, key)
print("The decrypted plaintext is:",plaintext)
```

![](../resources/ctf/grandfather/2.png)

<div style="page-break-after: always"></div>


# 16. Too close for comfort 😬
{:toc}
---
#### #Cryptography #Sage #Fermat

Challenge code:
```python
from gmpy2 import next_prime,invert
from Crypto.Util.number import *

flag = "flag{REDACTED}"
flag = bytes_to_long(flag.encode())
p = getPrime(512)
q = next_prime(p)
n = p*q
e = 65537
phi = (p-1)*(q-1)
d = invert(e,phi)
c = pow(flag,e,n)
print("n : ",n)
print("c : ",c)
```

In this code $q$ is assigned the value as next closet prime number to $p$, using `next_prime()` function.

On doing some google about the topic I found that if $p$ and $q$ are really close which in our case it most probably is, then we can factorize $n$ using *Fermat Factorization Method*.
Have a look at this video for better understanding of this Method:
- [Attacking RSA when p and q are close - YouTube](https://www.youtube.com/watch?v=C6abHMw8uoo)

To summarize the mathematic  part:

for $t = \lceil \sqrt{n} \rceil\ , \lceil \sqrt{n} \rceil + 1 \ , \lceil \sqrt{n} \rceil + 2 \ , ..$
we need to find $t$ such that
$t^2 - n = s^2$ is a perfect square.

<div style="page-break-after: always"></div>

Using python to factorize the $n$:
```python
from sage.all import *

n = 512626<..SNIP..>
e = 65537
c = 363527<..SNIP..>

def FermatFactor(n): 
    tmin = floor(sqrt(n))+1

    for t in range(tmin,n):
       s = sqrt(t*t - n)
       if floor(s) == s :
            return [t+s,t-s]
            break

factors = FermatFactor(n)
print("[+] Factors :",factors)
```

We found the factors of $n$.
![](0.png)

Now it's a smooth ride to calculate private key $d$ and decrypt the message using it.

![](../resources/ctf/close/1.png)

Calculated $d$.

![](../resources/ctf/close/2.png)

And we found the FLAG. 

<div style="page-break-after: always"></div>


# 17. Common Thread 🧵
{:toc}
---
#### #Cryptography #Sage #Modulo


Challenge Code:
```python
from Crypto.Util.number import getPrime,long_to_bytes,bytes_to_long as b2l
pt = b2l(b'############REDACTED#############')

e1 = 3
e2 = 65537

p = getPrime(512)
q = getPrime(512) 
n = p * q
print("p = ",p)
print("q = ",q)
print("n = ",n)

ct1 = pow(pt,e1,n)
ct2 = pow(pt,e2,n)

print("ct_1 = ",ct1)
print("ct_2 = ",ct2)

```

We can see same message has been encrypted using same modulo($n = p\times q$) twice using different $e$.

Looking about it on Internet it found this amazing article which can help you understand this attack and find our flag as well.
- [Common Modulus Attack | CryptoLearn](https://victim1307.github.io/cryptolearn/patterns/rsa/common-mod/)


![](../resources/ctf/common/1.png)

> Code credit goes to the writer of the above article. 

And flag it ours.

![](../resources/ctf/common/2.png)

<div style="page-break-after: always"></div>


# 18. Is it RSA ❓🔒
{:toc}
---
#### #Cryptography #RepeatingFactors #RSA


Challenge Code:
```python
from Crypto.Util.number import getPrime

p = getPrime(1024)
q = getPrime(1024)
r = getPrime(1024)
s = getPrime(1024)

m = #REDACTED
n1 = p*q
n2 = q*r
n3 = #REDACTED
e = 65537
c = pow(m,e,n3)

with open("cipher.txt","w") as f1:
    f1.write("n1 : {n1}\nn2 : {n2}\nn3 : {n3}\nc : {c}")
```

In the given code we can see $n_1$ and $n_2$ have a common factor $q$, if we find their GCD we got $q$ then from it we can can find $p$ and $r$.

![](../resources/ctf/is_ra/1.png)
Found the $q$, now can calculate $p$ and $r$ from $n_1$ and $n_2$ respectively.

![](../resources/ctf/is_ra/2.png)

Next step is to find $n_3$. If we go by the pattern it should be $n_3 = r \times s$, here $s$ is some number.

![](../resources/ctf/is_ra/3.png)

We got $s$ as well but it seems quite big as compared to $p$,$q$ and $r$.

![](../resources/ctf/is_ra/4.3.png)

On verifying it's bit length it came out to be `6142` bit's which it should not be, as mentioned in code s is `1024` bit long.

```python
s = getPrime(1024)
```

Lets say the $s$ we got is $s_1$. Now let's check whether $p$ and $q$ is factor of $s_1$ or not.

![](../resources/ctf/is_ra/5.png)

Yes they are it's factors as well therefore, Let
$$
s_2 = \frac{s_1}{p \times q}
$$ 
 
 ![](../resources/ctf/is_ra/5.1.png)

But still $s_2$ is of `4094` bit's long it could be possible that $s_2$ is multiple of 4 `1024` bits number. Let's check for any repetitive factors

![](5.2.png)

$p$ and $r$ were still the factors of $s_2$ and after dividing it by them we get $s_3$, which has bit length `2047`. At this point in $s_3$ one number is $s$ itself and one repetitive number, so lets find out that as well.

![](5.3.png)

$p$ was the last factor again and after dividing it we got $s$ and it's bit length is `1024` bits as well.

Therefore $n_3 = p\ . \ p \ . \ p \ . \ q \ . \ r \ . \ r \ . \ s$ 

We can verify that it will be equal.

![](../resources/ctf/is_ra/6.png)

Now we need to calculate *totient function* $\phi$, which in this is calculated as 

$$
\phi = p \ . p \ . \ (p-1) \ . \ (q-1) \ . \ (r -1) \ . \ r \ . \ (s-1)
$$

and after that private key $d$ as well and we get our FLAG

![](../resources/ctf/is_ra/7.png)


<div style="page-break-after: always"></div>

# 19. Decrypt The Secrets 🗝️🔓
{:toc}
---
#### #NetworkSecurity #TCP #ROT21 

Opening the File in Wireshark the first thing we can see was `hi` in TCP payload seems like some conversation.
![](../resources/ctf/de_secret/1.png)

Following through the conversation in TCP payload, they will be using some secret language that they know. 
![](../resources/ctf/de_secret/2.png)

All jumbled.
![](../resources/ctf/de_secret/3.png)

Following through the conversation I found something this packet, it is our flag but in this secret language. So I copied it and but it into [CyberChef](https://cyberchef.org/).

![](../resources/ctf/de_secret/4.png)

Since we know format of are flag and Little bit guessing it found it was using `ROT21` to rotate the letters in their conservation.
![](../resources/ctf/de_secret/5.png)

<div style="page-break-after: always"></div>

# 20. Packet Sniffing 📦👃
{:toc}
---
#### #NetworkSecurity #ICMP #HTTP #GET #Scapy

On opening the file in Wireshark we can see ICMP packets with some random payloads.
![](../resources/ctf/sniff/1.png)

But if we look at the end we can see 2 HTTP packets, one of them is downloading a JPEG image.
![](../resources/ctf/sniff/2.png)

In toolbar if we go to `File > Export Objects> HTTP`, we can see the Image listed but Wireshark seems having some issue saving it. So we can write a python script to do the job for us.

```python
from scapy.all import *
import binascii
import dpkt

def extract_jpeg_from_http(pcap_file, output_file):
    jpeg_data = b""
    packet_count = 0

    packets = rdpcap(pcap_file)

    for packet in packets:
        packet_count += 1
        if packet.haslayer(IP) and packet.haslayer(TCP):
            ip = packet[IP]
            tcp = packet[TCP]

            if packet_count == 33:
                http_data = bytes(tcp.payload)
                if b'Content-Type: image/jpeg' in http_data:
                    # Extract JPEG data from HTTP response
                    start_index = http_data.index(b'\r\n\r\n') + 4
                    jpeg_data += bytes(http_data[start_index:])
                    break

    if jpeg_data:
        print("[+] Generated")
        with open(output_file, 'wb') as outfile:
            outfile.write(jpeg_data)

# Usage
pcap_file = 'Packet Sniffing.pcap'
output_file = 'output.jpg'
extract_jpeg_from_http(pcap_file, output_file)

```

Code successfully extracted the JPEG file and it's our FLAG.

![](../resources/ctf/sniff/4.png)

<div style="page-break-after: always"></div>

# 21. One by One 1️⃣✋
{:toc}
---
#### #ICMP #Python3 


On opening the file in Wireshark we can see All ICMP packets having some payloads.
![](../resources/ctf/oneone/1.png)

Seeing the second packet and as the name of challenge tells us, Message is transferred character by character using ICMP packets.

![](../resources/ctf/oneone/2.png)

So we write a python script to extract the message for us:

```python
import pcapng
import dpkt

def extract_final_byte(pcapng_file):
    final_string = ""

    with open(pcapng_file, 'rb') as file:
        scanner = pcapng.FileScanner(file)

        for block in scanner:
            if isinstance(block, pcapng.blocks.EnhancedPacket):
                packet_data = block.packet_data
                eth = dpkt.ethernet.Ethernet(packet_data)
                
                if isinstance(eth.data, dpkt.ip.IP) and isinstance(eth.data.data, dpkt.icmp.ICMP):
                    icmp = eth.data.data
                    raw_data = icmp.pack()
                    final_byte = raw_data[-1]
                    final_string += chr(final_byte)

    return final_string

# Usage

pcap_file = 'One_by_One.pcapng'
final_string = extract_final_byte(pcap_file)
print("Final String:", final_string)
```

And here is the FLAG.

![](../resources/ctf/oneone/3.png)

<div style="page-break-after: always"></div>

# 22. Digital Vault 🗄️🔒
{:toc}
---
#### #NetworkSecurity #TCP #Scapy


Opening the file in Wireshark we can see all this TCP packets and in the first one we can see `hi`.

![](../resources/ctf/digiwalt/1.png)

Following the conservation one person is going to send a file. 
![](../resources/ctf/digiwalt/2.png)

From packet number 7 we can see it's sending a PNG file in parts.
![](../resources/ctf/digiwalt/3.png)

because if you notice the Seq Number of these packets no one is in continuous order (that's why Wireshark was not able to detect any object to export, as this object's Start is different packets which are not sent continuously unlike what happens normally on TCP) but they all possibly contains parts of same PNG image.

![](../resources/ctf/digiwalt/5.png)

So using a python script I extracted those packets and combined them to make a single PNG image which contained our flag.

![](../resources/ctf/digiwalt/4.png)

Code to extract the PNG image.
```python
from scapy.all import *
import dpkt

def extract_data_from_tcp_packets(pcap_file, output_file):
    tcp_data = b""
    start_extraction = False
    packet_count = 0

    packets = rdpcap(pcap_file)

    for packet in packets:
        packet_count += 1
        if packet.haslayer(IP) and packet.haslayer(TCP):
            ip = packet[IP]
            tcp = packet[TCP]

            if ip.src == "192.12.11.2" and packet_count >= 7:
                start_extraction = True
                tcp_data += bytes(tcp.payload)

    if tcp_data:
        with open(output_file, 'wb') as outfile:
            outfile.write(tcp_data)

# Usage

pcap_file = 'Digital_Vault.pcap'
output_file = 'testing_output2.png'
extract_data_from_tcp_packets(pcap_file, output_file)
```

<div style="page-break-after: always"></div>

# 23. Protocol Crackdown 🛡️🔒
{:toc}
---

#### #NetworkSecurity #TCP #ICMP #Python3 


After opening the file using Wireshark we can look at Protocol Hierarchy to see which type of packets are captured in this file. 
- TCP
- ICMP

![](../resources/ctf/proto_crack/1.png)

ICMP packets payload seems garbage value so not going to bother about ICMP packets for now.

![](../resources/ctf/proto_crack/2.png)

Looking at TCP packets we can see first packet's payload, it's a PNG file be transferred. 
![](../resources/ctf/proto_crack/3.png)

But if you look closely at Packet Len there are two type of TCP header one have length `733` and other having `100`. Payload of TCP packets having Len 100 are looking like random garbage stuff.

![](../resources/ctf/proto_crack/4.png)

So I am going to make a Python script that will extract the PNG image from TCP packets having length `733`.

![](../resources/ctf/proto_crack/5.png)

Code to extract the Image file:
```python
import pcapng
import dpkt

def extract_png_from_tcp_packets(pcapng_file, output_file):
    png_data = b""
    
    with open(pcapng_file, 'rb') as file:
        scanner = pcapng.FileScanner(file)

        for block in scanner:
            if isinstance(block, pcapng.blocks.EnhancedPacket):
                packet_data = block.packet_data
                eth = dpkt.ethernet.Ethernet(packet_data)
                
                if isinstance(eth.data, dpkt.ip.IP) and isinstance(eth.data.data, dpkt.tcp.TCP):
                    tcp = eth.data.data
                    if tcp.data and len(tcp.data) == 733:
                        png_data += tcp.data

    if png_data:
        with open(output_file, 'wb') as outfile:
            outfile.write(png_data)

# Usage
pcapng_file = 'Protocol_Crackdown.pcapng'
output_file = 'file111111111111111111.png'
extract_png_from_tcp_packets(pcapng_file, output_file)

```

