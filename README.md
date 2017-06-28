# MilterFrom
This milter compares the envelope sender with the sender specified in the mail header for authenticated users.

It aims to resolve the problem that OpenDKIM signs ALL mails with domains listed in its databases. If you have a multi user setup, user A "a@example.invalid" can send mails with the from field "From: b@example.invalid" and OpenDKIM signs it although user A should not be allowed to send authenticated mails from "b@example.invalid".

The postconf option "reject_authenticated_sender_login_mismatch" doesn't solve the problem at all, because it only enforces the envelope sender to be correct. This milter further ensures that the sender specified in the header matches the envelope sender.

## Beta
This code is beta. It would be gread if someone who has more experience with libmilter would look at my code and send me some feedback. The code is really short (one file with 270 lines) and based on the libmilter example. 

## Build
As always:
```bash
mkdir build
cd $_
cmake ..
make
```

## Postfix (on Debian)
```bash
groupadd milterfrom
useradd -g milterfrom -s /bin/false -d /var/spool/postfix/milterfrom milterfrom
adduser postfix milterfrom
mkdir /var/spool/postfix/milterfrom
chown milterfrom:milterfrom /var/spool/postfix/milterfrom
```

main.cf (If you don't use OpenDKIM, remove it):
```
smtpd_milters = unix:/milterfrom/milterfrom, unix:/opendkim/opendkim.sock
non_smtpd_milters = unix:/milterfrom/milterfrom, unix:/opendkim/opendkim.sock
```

## Run
```bash
./milterfrom -u milterfrom -g milterfrom -m 002 -d -p /var/run/milterfrom.pid -s /var/spool/postfix/milterfrom/milterfrom
```

## License
Licensed under the 3-Clause BSD License.
