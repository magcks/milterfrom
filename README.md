# MilterFrom
This milter compares the envelope sender with the sender specified in the mail header for authenticated users.

It aims to resolve the problem that OpenDKIM signs ALL mails with domains listed in its databases. If you have a multi user setup, user A "a@example.invalid" can send mails with the from field "From: b@example.invalid" and OpenDKIM signs it although user A should not be allowed to send authenticated mails from "b@example.invalid".

The postconf option "reject_authenticated_sender_login_mismatch" doesn't solve the problem at all, because it only enforces the envelope sender to be correct. This milter further ensures that the sender specified in the header matches the envelope sender.

## Beta
This code is beta. It would be great if someone who has more experience with libmilter would look at my code and send me some feedback. The code is really short (one file with 270 lines) and based on the libmilter example.

## Dependencies (as Debian package names)
* git cmake make gcc
* libmilter1.0.1 libmilter-dev

## Build and install
```bash
mkdir build
cd $_
cmake -DWITH_SYSTEMD=ON ..
make
make install # this installs the executable and the Systemd unit
systemctl daemon-reload
```

If you wish to install to a custom directory:
```bash
cmake -DWITH_SYSTEMD=ON -DCMAKE_INSTALL_PREFIX=/tmp/your/path ..
```

## Configure (on a Systemd and Postfix environment)
Add a user:
```bash
groupadd milterfrom
useradd -g milterfrom -s /bin/false -d /var/spool/postfix/milterfrom milterfrom
adduser postfix milterfrom
mkdir /var/spool/postfix/milterfrom
chown milterfrom:milterfrom /var/spool/postfix/milterfrom
```

Configure postfix to use the milter:
```
postconf -e "smtpd_milters = unix:/milterfrom/milterfrom$([[ $(postconf -h smtpd_milters) != "" ]] && echo -n ", " && postconf -h smtpd_milters)"
postconf -e "non_smtpd_milters = unix:/milterfrom/milterfrom$([[ $(postconf -h non_smtpd_milters) != "" ]] && echo -n ", " && postconf -h non_smtpd_milters)"
```

Start everything:
```bash
systemctl enable milterfrom
service milterfrom start
service postfix restart
```

## Example
```bash
openssl s_client -connect mail.coolkids.invalid -starttls smtp
```
```
CONNECTED(00000003)
[TLS stuff]
---
250 DSN
auth login
[...]
235 2.7.0 Authentication successful
mail from: chantal@coolkids.invalid
250 2.1.0 Ok
rcpt to: justin@external.invalid
250 2.1.5 Ok
data
354 End data with <CR><LF>.<CR><LF>
From: jacqueline@coolkids.invalid
To: justin@coolkids.invalid
Subject: Diese Mail ist super vertrauemswuerdig!11

Hey Justin,

i bims Jacqueline. Ich liebe dich lol!

Deine Jacqueline
.
550 5.7.1 Rejected due to unmatching envelope and header sender.
quit
221 2.0.0 Bye
closed
```

## Run
To start the daemon directly, run the following (Remove the `-d` to run in foreground):
```bash
milterfrom -u milterfrom -g milterfrom -m 002 -d -p /var/run/milterfrom.pid -s /var/spool/postfix/milterfrom/milterfrom
```

## License
Licensed under the 3-Clause BSD License.
