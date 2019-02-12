# Contribution Guide to gokrb5

If you're reading this then I guess you are interested in contributing to gokrb5 which is brilliant!
Thank you for your interest and taking the time to read this guide.

The information below should help you successfully contribute and by following these guidelines you are expressing the 
respect you have for the project and other contributors.

In return I will endeavour to respond promptly to issues and pull requests but please have patience as I do this in my 
spare time. Therefore it can take a few weeks for me to get round to some items.

A variety of contribution types are welcome:
* Raising bug reports.
* Suggesting enhancements.
* Updating and adding to documentation.
* Fixing bugs.
* Coding enhancements.
* Extending test coverage.

This project is not intended to be a support forum for general Kerberos issues and troubleshooting specific environment 
configurations.

## Ground Rules

Above all, be respectful and considerate of others. This means:
* Assume miss-communication is mistake not malice.
* Be patient. Many of those contributing are doing this out of good will and in their own time.
If something is really important to you, describe why and what the impact is so that others can understand and relate to 
it.
* Provide feedback in a constructive manner.

### Code Contribution Ground Rules

When contributing code please adhere to these responsibilities:
* Create issues (if one does not already exist) for any changes and enhancements that you wish to make.
Discuss how you intend to fix the bug or implement the enhancement to give the community a chance to comment and get us 
to the best solution.
* Do not create any new packages unless absolutely necessary.
* Do not alter the existing exported functions and constants unless absolutely necessary. 
This would require a major (vX.\_.\_) version update.
* Only add new exported functions and constants if absolutely necessary. 
This would require a minor (v\_.X.\_) version update.
* Keep your code platform agnostic.
* Ensure that any functions added or updated are covered by tests.
* Ensure tests pass.
* Ensure godoc comments are created or updated as required for any new or updated code.
* Ensure your contributions are formatted correctly with gofmt. The travis build will test this.
* Do not use external package dependencies.  
As gokrb5 is designed to be a core library used in other applications it is best to avoid dependencies the project has 
no control over, other than the Go standard library, as issues with any dependency could have large knock on effects.
* Provide useful commit messages.
* Pull requests must address one issue only and keep to the scope of the issue. This makes it easier to review and merge, so your contribution will get 
incorporated faster this way.
* Pull requests must have a message obeying this format:
```
<short summary starting with a verb in lowercase and less than 50 characters>

More detailed explanatory text. This should reference the related issue.
```
This to adhere to the [git best practice](https://git-scm.com/book/en/v2/Distributed-Git-Contributing-to-a-Project) and 
mirror the [contribution guidelines for the Go standard libarary](https://golang.org/doc/contribute.html).
An Example:
```
update to the godoc comments for the function Blah

The godoc comments to function subpkg.Blah have been updated to make it 
clearer as to what the function is for.
```

### Issue Raising Ground Rules
A good rule of thumb: The easier you make it for the reader of an issue to help the more help you'll get.

#### Bugs
When raising bugs please include the following items in your issue:
* The version of gokrb5 being used (vX.Y.Z or master or branch name).
* The version of Go being used (output of the ```go version``` command is handy).
* Details of the environment in which you are seeing the issue. For example, what is being used as the KDC, 
what the krb5.conf contains, etc.
* Details on how to re-create the issue.
* Details on what you are experiencing that indicates the issue.
* What you expected to see.
* In which gokrb5 package(s) you think the issue arises from.
* If the bug relates to compliance with an RFC please specify the RFC number and section you are referring to.

#### Enhancements 
When raising enhancement requests or suggestions please include the following:
* What the enhancment is or would do.
* Why you need the enhancement or why you think it would be a good idea.
* Any suggestions you may have on how to implement.

## Tips

### Running Tests
Running the tests without any particular switches runs only the unit tests.

It is recommended to run tests with the ```-race``` argument.

There are integration tests that run against various other network services such as KDCs, HTTP web servers, DNS servers, 
etc. To run these pass ```-tags=integration``` as an argument to the go test command.
There are vagrant and docker resources available to spin up these network services. See the 
[readme](https://github.com/jcmturner/gokrb5/blob/master/testenv/README.md) in the testenv directory for instructions.
