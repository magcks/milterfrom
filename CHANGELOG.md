#milterfrom CHANGELOG

Version 1.0.1  2023-08-30

* Add logging to log mismatch event using syslog (mail.notice)
* Add VERSION declaration and help/version command line options
* Add CHANGELOG.md to repository for tracking

Version 1.0.2  2023-09-18

* Fixed bug on null sender to SMFIS_ACCEPT and no more filtering
* Added syslog on null sender event with connection details (IP,name)
* Changed syslog to be from log_event routine
