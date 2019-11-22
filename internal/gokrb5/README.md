# Background

This directory is essentially a fork of https://github.com/jcmturner/gokrb5.

As of when this was written (Nov. 2019), gokrb5 was the most fully-featured
Kerberos client written in Go. We, however, needed some bug fixes merged before
we would be able to take advantage of the library for use in our CLI handler.
The gokrb5 library appeared to not have received any maintenance since June
of 2019.

We considered maintaining a fork of the library, but didn't want to become the
keepers of the Go Kerberos client for the public at large. Thus, we decided to
place the library into an internal folder to flag that it's not intended for
wider consumption.

This has the downside of making it more difficult to pull in changes to the
upstream gokrb5 library. However, we don't anticipate many at this time due
to it being under low or no maintenance.

In the future if our PRs are ever merged and the library has valuable fixes
or seems more actively maintained, we may wish to switch back to using it
directly. At that time, we should carefully diff our two libraries to see
if ours has any fixes the other doesn't have, and resolve those differences
if so.

The gokrb5 Apache 2 license appears to find this usage permissible. Also, we
are grateful to the authors of that library for the incredible ground they
have cut on the Kerberos client for Go.
