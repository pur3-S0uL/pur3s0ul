---
layout: default
title: "CookieMonster"
parent: "Digital Defenders Cybersecurity CTF"
---

# CookieMonster 🍪
**Digital Defenders Cybersecurity CTF 2023 WriteUp**

Website:
![](../../resources/ctf/cookiemonster/1.png)

As name of this challenge is suggesting, looking the cookies.

![](../../resources/ctf/cookiemonster/2.png)
I put the value of `cookie` in [CyberChef](https://cyberchef.org/) and after
- URL Decoding
- Base64 decoding

we can see it just a JSON value.
![](../../resources/ctf/cookiemonster/3.png)

After modifying the admin value to 1 and encoding it back again. I submitted it in the browser and refreshed the page.
![](../../resources/ctf/cookiemonster/4.png)

And we can see the FLAG.
![](../../resources/ctf/cookiemonster/5.png)
