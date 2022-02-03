# Portfolio

## OverTheWire's capture the flag: Bandit
All the while studying for the [cybersecurity bootcamp at University of Toronto](https://bootcamp.learn.utoronto.ca/cybersecurity/), I decided to test my existing skills with linux and level up my knowledge of networks.

OverTheWire offers different capture the flag so called *wargames*. [Bandit](https://overthewire.org/wargames/bandit) is all about extracting the password to the next level using very limited hints.

### useful resources
Here are some links to understand bash a little better
- https://ss64.com/bash/ssh.html online `man` pages with more examples and easier to read
- http://www.bashoneliners.com what it says on the tin. Practical to avoid reinventing the wheel

> :warning: the following will only make sense together with the hints on [OverTheWire Bandit](https://overthewire.org/wargames/bandit)
#### level 0 :bangbang:
First steps first: to `ssh` into bandit
```bash
ssh bandit0@bandit.labs.overthewire.org -p 2220
bandit0
```

#### level 1:bangbang:
```bash
ssh bandit1@bandit.labs.overthewire.org -p 2220
```
password: `boJ9jbbUNNfktd78OOpsqOltutMc3MY1`

#### level 2:bangbang:
password: `CV1DtqXWVFXTvM2F0k09SHz0YwRINYA9`

#### level 3:bangbang:
password: `UmHadQclWmgdLOKQ3YNgjWxGoRMb5luK`

#### level 4:bangbang:
password: `pIwrPrtPN36QITSp3EQaw936yaFoFgAB`

#### level 5:bangbang:
``` bash
find -H ! -executable -size 1033c
```
password: `koReBOKuIDDepwhWk7jZC0RTdopnAYKh`

#### level 6:bangbang:
password: `DXjZPULLxYr17uwoI01bNLQbtFemEgo7`

#### level 7:bangbang:
``` bash
find -user bandit7 -group bandit6 -size 33c | less
cat ./var/lib/dpkg/info/bandit7.password
```
password: `HKBPTKQnIay4Fw76bEy8PVxKEDQRKTzs`

#### level 8:bangbang:
``` bash
grep millionth data.txt
```
password: `cvX2JJa4CFALtqS87jk27qwqGhBM9plV`

#### level 9:bangbang:
```bash
sort data.txt | uniq -u
```
password: `UsvVyFSfZZWbi6wgC7dAFyFuR6jQQUhR`

#### level 10:bangbang:
```bash
strings = data.txt | grep ===
```
password: `truKLdjsbJ5g7yyJ2X2R0o3a5HQJFuLk`

#### level 11:bangbang:
```bash
base64 -di data.txt
```
password: `IFukwKGsFW8MOq3IRFqrxE1hxTNEbUPR`

#### level 12:bangbang:
```bash
tr 'A-Za-z' 'N-ZA-Mn-za-m' < data.txt
```
password: `5Te8Y4drgCRfCx8ugdwuEX8KFC6k2EUu`

#### level 13:bangbang:
Clearly a hexdump therefor `xxd`
```bash
xxd -r data.txt > data.txt-xxd
```
`File` to check what type.
We now have to `gzip`, `tar`, and `bzip2` your way to heaven

password: `8ZjyCRiBWFYkneahHwxCv3wb2a1ORpYL`

#### level 14
``` bash
bandit13@bandit:~$ ls -la
total 24
drwxr-xr-x  2 root     root     4096 May  7  2020 .
drwxr-xr-x 41 root     root     4096 May  7  2020 ..
-rw-r--r--  1 root     root      220 May 15  2017 .bash_logout
-rw-r--r--  1 root     root     3526 May 15  2017 .bashrc
-rw-r--r--  1 root     root      675 May 15  2017 .profile
-rw-r-----  1 bandit14 bandit13 1679 May  7  2020 sshkey.private
```
So we can examine the `sskey.private` file, and see there is a single key stored
``` bash
-----BEGIN RSA PRIVATE KEY-----
MIIEpA [...] elRi2E2aEzA==
-----END RSA PRIVATE KEY-----
```
which we can use by telling `ssh` to use it explicitly with the option `-i` for "identity_file".
``` bash
bandit13@bandit:~$ ssh -i sshkey.privates bandit14@bandit.labs.overthewire.org -p 2220
```
This started hanging, so I used `localhost` instead
``` bash
ssh -i sshkey.private bandit14@localhost
```
which worked to log in `bandit14` without being prompted for a password at all. Then we can just go and get the password for this level
``` bash
bandit14@bandit:~$ cat /etc/bandit_pass/bandit14
4wcYUJFw0k0XLShlDzztnTBHiqxU3b3e
```
password: `4wcYUJFw0k0XLShlDzztnTBHiqxU3b3e`

#### level 15
`Telnet` lets you communicate directly with a port. At its most basic use, it tests if the port is open. In this case, you can submit `bandit14` password and receive `bandit15`'s'
``` bash
bandit14@bandit:~$ telnet localhost 30000
Trying 127.0.0.1...
Connected to localhost.
Escape character is '^]'.
4wcYUJFw0k0XLShlDzztnTBHiqxU3b3e
Correct!
BfMYroe26WYalil77FoDi9qh59eK5xNr

Connection closed by foreign host.
```
password: `BfMYroe26WYalil77FoDi9qh59eK5xNr`

#### level 16
In the output's 5th paragraph, it is interesting to point out `Verification error: self signed certificate` was flagged. Knowing this is all internal to Bandit/OTW, it felt it safe to ignore. It is only a warning, and not an error message after all.

Otherwise, similar to level 15, but using `openssl`

``` bash
openssl s_client -connect localhost:30001
CONNECTED(00000003)
depth=0 CN = localhost
verify error:num=18:self signed certificate
verify return:1
depth=0 CN = localhost
verify return:1
---
Certificate chain
 0 s:/CN=localhost
   i:/CN=localhost
---
Server certificate
-----BEGIN CERTIFICATE-----
MIICB [...] s9Iz
-----END CERTIFICATE-----
subject=/CN=localhost
issuer=/CN=localhost
---
No client certificate CA names sent
Peer signing digest: SHA512
Server Temp Key: X25519, 253 bits
---
SSL handshake has read 1019 bytes and written 269 bytes
Verification error: self signed certificate
---
New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384

[TRUNCATED]

    Start Time: 1641136447
    Timeout   : 7200 (sec)
    Verify return code: 18 (self signed certificate)
    Extended master secret: yes
---
```
at this point we type in the last password and great
``` bash
BfMYroe26WYalil77FoDi9qh59eK5xNr
Correct!
cluFn7wTiGryunymYOu4RcffSxQluehd

closed
```
password: `cluFn7wTiGryunymYOu4RcffSxQluehd`

#### level 17
For this one, I was immediately temped to write a simple `for` loop. I find the http://www.bashoneliners.com a great place to look up how to do more involved bash scripting while avoiding writing a program if I am only going to use it once. With the power of `alias`, one can always use them as "programs" later. It's a quick and dirty way to do it.

My version:
``` bash
for port in {31000..32000} ; do echo $port ; telnet localhost $port ; done
```
and Bashoneliner's
``` bash
for i in {31000..32000}; do (echo < /dev/tcp/127.0.0.1/$i) &>/dev/null && printf "\n[+] Open Port at\n: \t%d\n" "$i" || printf "."; done
```
but I looked further knowing this must have been automated better before me: after all, scanning for an open port has got to be one of the most used task in cybersecurity. Lo' and behold `nmap`. Note it is not installed everywhere. Just something to keep in mind if you cannot install programs on the machine you are on for whatever reason.
>:bangbang:

``` bash
nmap -p31000-32000 localhost
openssl s_client -connect localhost:31790
```
``` bash
bandit16@bandit:~$ openssl s_client -connect localhost:31790
CONNECTED(00000003) [TRUNCATED OUTPUT]
```
eventually we get a prompt to input the password of level 18
``` bash
---
cluFn7wTiGryunymYOu4RcffSxQluehd
Correct!
-----BEGIN RSA PRIVATE KEY-----
MIIE[...]/ujbjY=
-----END RSA PRIVATE KEY-----

closed
```
Armed with the key, we create a file with it to feed it to `ssh`

``` bash
bandit16@bandit:~$ vim /tmp/toerase/sshkey
bandit16@bandit:/tmp/toerase$ ssh -i sshkey bandit17@localhost
Could not create directory '/home/bandit16/.ssh'.
The authenticity of host 'localhost (127.0.0.1)' cannot be established.
ECDSA key fingerprint is SHA256:98UL0ZWr85496EtCRkKlo20X3OPnyPSB5tB5RPbhczc.
Are you sure you want to continue connecting (yes/no)? yes
Failed to add the host to the list of known hosts (/home/bandit16/.ssh/known_hosts).
This is a OverTheWire game server. More information on http://www.overthewire.org/wargames

@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
Permissions 0644 for 'sshkey' are too open.
It is required that your private key files are NOT accessible by others.
This private key will be ignored.
Load key "sshkey": bad permissions
bandit17@localhost's password:
```
This error message tells us we need to change the permissions of the sshkey file, so let's do that
``` bash
bandit16@bandit:/tmp/toerase$ chmod 600 sshkey
bandit16@bandit:/tmp/toerase$ ssh -i sshkey bandit17@localhost
```
and then same as level 14:
```bash
bandit17@bandit:~$ cat /etc/bandit_pass/bandit17
xLYVMN9WE5zQ5vHacb0sZEVqbrp7nBTn
```
password: `xLYVMN9WE5zQ5vHacb0sZEVqbrp7nBTn`

#### level 18
This is exactly what the `diff` command was made for
``` bash
bandit17@bandit:~$ diff passwords.new passwords.old
42c42
< kfBf3eYk5BPBRzwjqutbbfE887SVc5Yd
---
> w0Yfolrc5bwjS4qw5mq1nnQi6mF03bii
```
password: `kfBf3eYk5BPBRzwjqutbbfE887SVc5Yd`

#### level 19
This is what the `--norc` flag was made for
``` bash
ssh bandit18@bandit.labs.overthewire.org -p 2220 "bash --norc"     
```

password: `IueksS7Ubh8G3DCwVzrTd8rAVOwq3M5x`

#### level 20
This one is self-explanatory once we execute the program
``` bash
bandit19@bandit:~$ ./bandit20-do
Run a command as another user.
  Example: ./bandit20-do id
```
so there is only one thing left to do, which we have done in previous levels and peep into the passwords repository using the persmission of the next level
``` bash
bandit19@bandit:~$ ./bandit20-do cat /etc/bandit_pass/bandit20
GbKksEFF4yrVs6il55v6gwY5aVje5f0j
```
password: `GbKksEFF4yrVs6il55v6gwY5aVje5f0j`

#### level 21 :bangbang:
First execute the new program
``` bash
bandit20@bandit:~$ ./suconnect
Usage: ./suconnect <portnumber>
This program will connect to the given port on localhost using TCP. If it receives the correct password from the other side, the next password is transmitted back.
```

Tab 1
```
bandit20@bandit:~$ nc -lp 4000
```
Which opens and listens to port 50'000. So let's check with nmap on on Tab 2
```
bandit20@bandit:~$ nmap  localhost

Starting Nmap 7.40 ( https://nmap.org ) at 2022-01-13 19:32 CET
Nmap scan report for localhost (127.0.0.1)
Host is up (0.0014s latency).
Not shown: 996 closed ports
PORT      STATE SERVICE
22/tcp    open  ssh
113/tcp   open  ident
4000/tcp  open  remoteanything           <---- here it appears to be OPENED
30000/tcp open  ndmps

Nmap done: 1 IP address (1 host up) scanned in 0.20 seconds
```
Ok so now we give it the password
Tab 1
```
nc -lp 4000 < /etc/bandit_pass/bandit20
```
Tab 2
```
bandit20@bandit:~$ ./suconnect 4000
Read: GbKksEFF4yrVs6il55v6gwY5aVje5f0j
Password matches, sending next password
```
The password is then returned in tab 1: `gE269g2h3mw3pwgrj0Ha9Uoqen1c9DGr`

#### level 22 :bangbang:
```
bandit21@bandit:/etc/cron.d$ ls -la
total 36
drwxr-xr-x  2 root root 4096 Jul 11  2020 .
drwxr-xr-x 87 root root 4096 May 14  2020 ..
-rw-r--r--  1 root root   62 May 14  2020 cronjob_bandit15_root
-rw-r--r--  1 root root   62 Jul 11  2020 cronjob_bandit17_root
-rw-r--r--  1 root root  120 May  7  2020 cronjob_bandit22
-rw-r--r--  1 root root  122 May  7  2020 cronjob_bandit23
-rw-r--r--  1 root root  120 May 14  2020 cronjob_bandit24
-rw-r--r--  1 root root   62 May 14  2020 cronjob_bandit25_root
-rw-r--r--  1 root root  102 Oct  7  2017 .placeholder
```
Let's us see that where there's a `FILENAME_root` there is twice the data. Indeed, there are two lines when there is no root, and a `reboot` signal is being sent
```
bandit21@bandit:/etc/cron.d$ for FILE in ./* ; do echo $FILE ; cat $FILE ; done
./cronjob_bandit15_root
* * * * * root /usr/bin/cronjob_bandit15_root.sh &> /dev/null
./cronjob_bandit17_root
* * * * * root /usr/bin/cronjob_bandit17_root.sh &> /dev/null
./cronjob_bandit22
@reboot bandit22 /usr/bin/cronjob_bandit22.sh &> /dev/null
* * * * * bandit22 /usr/bin/cronjob_bandit22.sh &> /dev/null
./cronjob_bandit23
@reboot bandit23 /usr/bin/cronjob_bandit23.sh  &> /dev/null
* * * * * bandit23 /usr/bin/cronjob_bandit23.sh  &> /dev/null
./cronjob_bandit24
@reboot bandit24 /usr/bin/cronjob_bandit24.sh &> /dev/null
* * * * * bandit24 /usr/bin/cronjob_bandit24.sh &> /dev/null
./cronjob_bandit25_root
* * * * * root /usr/bin/cronjob_bandit25_root.sh &> /dev/null
```

Then it's a question of following the breadcrumbs:
```
bandit21@bandit:/etc/cron.d$ less /usr/bin/cronjob_bandit22.sh
bandit21@bandit:/etc/cron.d$ less /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
```

password: `Yk7owGAcWjwMVRwrTesJEwB7WVOiILLI`

#### level 23
Opening the relevant files gives us (similar with `bandit23`)
```bash
bandit22@bandit:/etc/cron.d$ cat cronjob_bandit22
@reboot bandit22 /usr/bin/cronjob_bandit22.sh &> /dev/null
* * * * * bandit22 /usr/bin/cronjob_bandit22.sh &> /dev/null
```
which means that script `/usr/bin/cronjob_bandit22.sh` is executed and outputting  to `/dev/null`. That last file is empty so let's investigate the script being executed.

``` bash
#!/bin/bash

myname=$(whoami)
mytarget=$(echo I am user $myname | md5sum | cut -d ' ' -f 1)

echo "Copying passwordfile /etc/bandit_pass/$myname to /tmp/$mytarget"

cat /etc/bandit_pass/$myname > /tmp/$mytarget
```
Since we are logged in as `bandit22` that is what `myname` is. Since the password we are looking for is being copied to `/tmp/$mytarget`, let's find out what that target is exactly and use that information to retrieve it, but as `bandit23`
``` bash
bandit22@bandit:/usr/bin$ echo I am user bandit23 | md5sum | cut -d ' ' -f 1
8ca319486bfbbc3663ea0fbe81326349
bandit22@bandit:/usr/bin$ cat /tmp/8ca319486bfbbc3663ea0fbe81326349
jc1udXuA1tiHqjIsL8yaapX5XIAI6i0n
```

password: `jc1udXuA1tiHqjIsL8yaapX5XIAI6i0n`

#### level 24
We can completely bypass this one by just repeating what we did in the previous level
``` bash
bandit23@bandit:/var/spool$ echo I am user bandit24 | md5sum | cut -d ' ' -f 1
ee4ee1703b083edac9f8183e4ae70293
bandit23@bandit:/var/spool$ cat /tmp/ee4ee1703b083edac9f8183e4ae70293
UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ
```
password: `UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ`

#### level 25
Let's first check what happens if we just communicate with that port
``` bash
bandit24@bandit:~$ telnet localhost 30002
Trying 127.0.0.1...
Connected to localhost.
Escape character is '^]'.
I am the pincode checker for user bandit25. Please enter the password for user bandit24 and the secret pincode on a single line, separated by a space.
```
so let's write a script for that. For permission purposes, we will do so in a new `/tmp/` directory.
``` bash
#!/bin/bash

for a in {0..9}; do
    for b in {0..9}; do
        for c in {0..9}; do
            for d in {0..9}; do
                echo UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ $a$b$c$d | nc localhost 30002
            done
        done
    done
done
```
but this is inefficient and turns out bash will know to keep 4 digits if you say `0000`. So I used the principle behind [Effy Min's script](https://write.as/effyverse/bandit-lv-24-brute-force-password-script)
``` bash
#!/bash/bin

for i in {0000..9999}; do
       echo UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ $i | nc localhost 30002
done
```
password: `uNG9O58gUE7snukf3bvZ0rxhtnjzSGzG`

#### level 26
As promised, reaching level 26 is easy, since we used this exact method to get into bandit level 15:
``` bash
bandit25@bandit:~$ ssh -i bandit26.sshkey bandit26@localhost
```
the question is staying there...

We know that all passwords are stored in `/etc/bandit_pass/banditXX` where `XX` is the level. Of course, the permissions to read said password is restricted to the level protected by the same password.

So let's explore what else `/etc` has in terms on passwords:
```bash
bandit25@bandit:~$ ls -l /etc/ | grep pass
drwxr-xr-x 2 root   root    4096 May  7  2020 bandit_pass
-rw-r--r-- 1 root   root    3595 May  7  2020 passwd
-rw------- 1 root   root    3579 May  7  2020 passwd-
```
That top one looks promising
```bash
bandit25@bandit:~$ cat /etc/passwd | grep bandit26
bandit26:x:11026:11026:bandit level 26:/home/bandit26:/usr/bin/showtext
bandit25@bandit:~$ cat /usr/bin/showtext
#!/bin/sh

export TERM=linux

more ~/text.txt
exit 0
```
There it is, when this script executes, it `exit` out of our `ssh` connection.

Trying to pass a command with `ssh` doesn't work because the `/usr/bin/showtext` is being executed before hand.
``` bash
bandit25@bandit:/tmp/lemon$ ssh -t -i ~/bandit26.sshkey bandit26@localhost 'cat *'
Could not create directory '/home/bandit25/.ssh'.
The authenticity of host 'localhost (127.0.0.1)' cannot be established.
ECDSA key fingerprint is SHA256:98UL0ZWr85496EtCRkKlo20X3OPnyPSB5tB5RPbhczc.
Are you sure you want to continue connecting (yes/no)? yes
Failed to add the host to the list of known hosts (/home/bandit25/.ssh/known_hosts).
This is a OverTheWire game server. More information on http://www.overthewire.org/wargames

  _                     _ _ _   ___   __  
 | |                   | (_) | |__ \ / /  
 | |__   __ _ _ __   __| |_| |_   ) / /_  
 | '_ \ / _` | '_ \ / _` | | __| / / '_ \
 | |_) | (_| | | | | (_| | | |_ / /| (_) |
 |_.__/ \__,_|_| |_|\__,_|_|\__|____\___/
Connection to localhost closed.'
```
Even changing from the default shell by passing `chsh` will not work.

Clearly we are not going to solve this level at the `ssh` stage. So we need to "attack" this different shell `bandit26` runs.  It is in fact the `showtext` above. Another way to get that hint is to look into what shells are available on the bandit server
``` bash
bandit25@bandit:/$ cat etc/shells
# /etc/shells: valid login shells
/bin/sh
/bin/dash
/bin/bash
/bin/rbash
/usr/bin/screen
/usr/bin/tmux
/usr/bin/showtext
```
and confirm it is indeed `/usr/bin/showtext` by doing
```bash
bandit26:x:11026:11026:bandit level 26:/home/bandit26:/usr/bin/showtext
```
We cannot tell `bandit26` to use a different shell by changing that file without `root` access unfortunately.

:bangbang: SOMETHING SOMETHING ABOUT `more` being what is executed at launch, right before `exit` is sent. So let us suspend `more`, use `v` to switch to edit mode, then press `ESC` to execute any commands we want!

#### level 27 :bangbang:
 `Run a command as another user. Example: %s id`

 ``` bash
 :! ~/bandit27-do                                                                                        
[No write since last change]
Run a command as another user.
  Example: /home/bandit26/bandit27-do id

shell returned 1
```
then
``` bash
:! ~/bandit27-do cat /etc/bandit_pass/bandit27
[No write since last change]
3ba3118a22e93127a4ed485be72ef5ea
```
password: `3ba3118a22e93127a4ed485be72ef5ea`

#### level 28
```bash
bandit27@bandit:~$ mkdir /tmp/<your created tmp directory>/git
bandit27@bandit:~$ git clone ssh://bandit27-git@localhost/home/bandit27-git/repo /tmp/lemon/git
```
entering the password for `bandit27` and boom it works. Now we can read the password from the only file in that new directory.

password: `0ef186ac70e04ea33b4c1853d2526fa2`

#### level 29
Same principle as before, but now we arrive at
``` bash
# Bandit Notes
Some notes for level29 of bandit.

## credentials

- username: bandit29
- password: xxxxxxxxxx
```

So let us see in the logs if there was a time where the `README.md` file had the password:
``` bash
bandit28@bandit:/tmp/lemon/repo$ git log
commit edd935d60906b33f0619605abd1689808ccdd5ee
Author: Morla Porla <morla@overthewire.org>
Date:   Thu May 7 20:14:49 2020 +0200

    fix info leak

commit c086d11a00c0648d095d04c089786efef5e01264
Author: Morla Porla <morla@overthewire.org>
Date:   Thu May 7 20:14:49 2020 +0200

    add missing data

commit de2ebe2d5fd1598cd547f4d56247e053be3fdc38
Author: Ben Dover <noone@overthewire.org>
Date:   Thu May 7 20:14:49 2020 +0200

    initial commit of README.md
bandit28@bandit:/tmp/lemon/repo$ git checkout c086d11a00c0648d095d04c089786efef5e01264
Note: checking out 'c086d11a00c0648d095d04c089786efef5e01264'.
```
Now revisiting `README.md` with get the password.

password: `bbc96594b4e001778eee9975372716b2`

#### level 30
Similar to the above level, but this time we investigate branches
``` bash
bandit29@bandit:/tmp/lemon/repo$ git branch -a
* (HEAD detached at 208f463)
  master
  remotes/origin/HEAD -> origin/master
  remotes/origin/dev
  remotes/origin/master
  remotes/origin/sploits-dev
bandit29@bandit:/tmp/lemon/repo$ git checkout   remotes/origin/dev
Previous HEAD position was 208f463... fix username
HEAD is now at bc83328... add data needed for development
bandit29@bandit:/tmp/lemon/repo$ cat README.md
# Bandit Notes
Some notes for bandit30 of bandit.

## credentials

- username: bandit30
- password: 5b90576bedb2cc04c86a9e924ce42faf
```

password: `5b90576bedb2cc04c86a9e924ce42faf`

#### level 31
This time the `README.md` has the simple message
```
just an empty file...muahaha
```
Going through possible things you can do with `git` lands you investigating tags
``` bash
bandit30@bandit:/tmp/lemon$ git tag
secret
bandit30@bandit:/tmp/lemon$ git show secret
47e603bb428404d265f59c42920d81e5
```

password: `47e603bb428404d265f59c42920d81e5`

#### level 31
Our new file now gives us clear instructions:
```bash
This time your task is to push a file to the remote repository.

Details:
    File name: key.txt
    Content: 'May I come in?'
    Branch: master
```
So let us do just that:
```bash
bandit31@bandit:/tmp/lemon/repo$ vim key.txt
bandit31@bandit:/tmp/lemon/repo$ git add -f key.txt
bandit31@bandit:/tmp/lemon/repo$ git push
```
password: `56a9bf19c63d650ce78e6ec0354ee45e`

#### level 32
