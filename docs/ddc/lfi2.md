---
layout: default
title: "Laughable File Infiltration 2"
parent: "Digital Defenders Cybersecurity CTF"
---

# Laughable File Infiltration 2 📂
**Digital Defenders Cybersecurity CTF 2023 WriteUp**

**Website**:
![](../../resources/ctf/lfi2/1.png)

Intercepting the request using Burp and we can see How a local file is loaded using POST parameter.
![](../../resources/ctf/lfi2/2.png)

Requested for `/etc/passwd` file and we got it back.
![](../../resources/ctf/lfi2/3.png)

On request for `flag.txt`, we are getting the response `.txt` not found ?!!.
![](../../resources/ctf/lfi2/4.png)
There seems to be some kind of filtering which is removing `flag` word from the parameter data.
![](../../resources/ctf/lfi2/5.png)
`flagflag` was also removed.
I am guessing filter goes in one pass and removes `flag` word. So we can bypass it if we pass `flflagag` after filtering it will become `flag` and we can access our FLAG.

![](../../resources/ctf/lfi2/6.png)

It Worked !!!