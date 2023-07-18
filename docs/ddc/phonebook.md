---
layout: default
title: "PhoneBook"
parent: "Digital Defenders Cybersecurity CTF"
---

# Phone Book 📞
**Digital Defenders Cybersecurity CTF 2023 WriteUp**

Challenge webpage:
![](../../resources/ctf/phonebook/1.png)

On clicking `Click Here` button we get a Name and Phone Number, but if you look at the URL, the user details which this page is displaying is associated with `id=1`.
![](../../resources/ctf/phonebook/2.png)

On requesting `id=2`, we get some other user's details.
![](../../resources/ctf/phonebook/3.png)

On requesting `id=0` we got the FLAG.
![](../../resources/ctf/phonebook/4.png)