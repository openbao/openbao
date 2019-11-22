# Background

This directory is essentially a fork of https://github.com/jcmturner/gokrb5.

As of when this was written (Nov. 2019), gokrb5 is the most fully-featured
Kerberos client written in Go. We've needed some bug fixes merged before
the upstream library can integrate them, so for now these changes will live
as an internal package.

We considered maintaining a fork of the library, but didn't want to become the
keepers of the Go Kerberos client for the public at large. Thus, we decided to
place the library into an internal folder to flag that it's not intended for
wider consumption.

This has the downside of making it more difficult to pull in changes to the
upstream gokrb5 library.

In the future if our PRs are ever merged and the library has valuable fixes
or seems more actively maintained, we may wish to switch back to using it
directly. At that time, we should carefully diff our two libraries to see
if ours has any fixes the other doesn't have, and resolve those differences
if so.

We are grateful to the authors of that library for the incredible ground they
have cut on the Kerberos client for Go.

## All Files Should Be Presumed Modified

No files in this version of the gokrb5 library should be assumed to be the
same as those in https://github.com/jcmturner/gokrb5. Not only has this
library received multiple modifications, but the original library may receive
additional modifications that are not present here. All files here should be
presumed to be changed unless proven otherwise.
