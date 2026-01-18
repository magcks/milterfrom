#milterfrom CHANGELOG

Version 1.0.4 2025-10-05
* Added optional argument `-r` to reject on multiple From: address fields like From:Grouping<g@example> <auth@example.com>
* Added optional argument `-n`  to reject null sender unless authentication matches the From: address.
* See CERT/CC disclosure VU#517845 kb.cert.org/vuls/id/517845


Version 1.0.3 2025-09-24
* Added verification of no control characters inside carrots.
[See references https://blog.slonser.info/posts/email-attacks/ ]

Version 1.0.2  2023-09-18

* Fixed bug on null sender to SMFIS_ACCEPT and no more filtering
* Added syslog on null sender event with connection details (IP,name)
* Changed syslog to be from log_event routine

Version 1.0.1  2023-08-30

* Add logging to log mismatch event using syslog (mail.notice)
* Add VERSION declaration and help/version command line options
* Add CHANGELOG.md to repository for tracking


