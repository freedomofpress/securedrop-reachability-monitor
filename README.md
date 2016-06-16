Freedom of the Press Foundation does monitoring of certain SecureDrop instances.
To check which instances are up at a given time, we've been using Nagios. For
whatever reason, Nagios gives a lot of false positives, telling us sites are up
when they're not. The Nagios utilites are not really Tor aware, so they provide
no tools for further introspection into why we are getting these false postives.
This repo contains a Python monitor that uses stem to log a great deal of
information from the Tor process, which should help us figure out this issue.
