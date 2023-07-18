---
layout: default
title: "Laughable File Infiltration"
parent: "Digital Defenders Cybersecurity CTF"
---

# Laughable File Infiltration 📂
**Digital Defenders Cybersecurity CTF 2023 WriteUp**

Website:
![](../../resources/ctf/lfi1/1.png)

On opening a page we can look at URL and determine that `view` page is loading files locally using value passed in GET parameter `file`. 
![](../../resources/ctf/lfi1/2.png)

Testing **Local File Inclusion** by requesting `/etc/passwd` file.

![](../../resources/ctf/lfi1/3.png)
We got the file. Now we can request for Flag.
![](../../resources/ctf/lfi1/4.png)