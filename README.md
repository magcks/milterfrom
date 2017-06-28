# MilterFrom
This milter is used to compare the envelope sender with the sender specified in the mail header for authenticated users.

It aims to resolve the problem that OpenDKIM signs ALL mails with domains listed in its databases. If you have a multi user setup user A "a@example.invalid" can send mails with the from field "From: b@example.invalid" and OpenDKIM signs it although user A should not be allowed to send authenticated mails from b@example.invalid.

The postconf option "reject_authenticated_sender_login_mismatch" doesn't solve the problem at all, because it only enforces the envelope sender to be correct. This milter furhter ensures that the sender specified in the header matches the envelope sender.

## Beta
This code is beta. Someone who has more experience in using libmilter should look over the code and send me some feedback. The code is really short (one file with 209 lines) and based on the libmilter example. 

## Build
As always:
```bash
mkdir build
cd $_
cmake ..
make
```

## Run
```bash
./milterfrom -d -p pidfile.pid -s /var/spool/postfix/themilter
```

## License
Licensed under the 3-Clause BSD License.
