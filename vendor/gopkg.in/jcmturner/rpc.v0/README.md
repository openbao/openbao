# RPC
[![GoDoc](https://godoc.org/gopkg.in/jcmturner/rpc.v0?status.svg)](https://godoc.org/gopkg.in/jcmturner/rpc.v0) [![Go Report Card](https://goreportcard.com/badge/gopkg.in/jcmturner/rpc.v0)](https://goreportcard.com/report/gopkg.in/jcmturner/rpc.v0) [![Build Status](https://travis-ci.org/jcmturner/rpc.svg?branch=master)](https://travis-ci.org/jcmturner/rpc)


This project relates to [CDE 1.1: Remote Procedure Call](http://pubs.opengroup.org/onlinepubs/9629399/)

It is a partial implementation that mainly focuses on marshaling NDR encoded byte streams into Go structures.

## Unstable API
Currently this library is at a v0 status to reflect there will be breaking changes in the API without major version revisions.
Please consider this if you adopt this library in your project.

## Help Wanted
* Reference test vectors needed: It has been difficult to implement due to a lack of reference test byte streams in the 
standards documentation. Test driven development has been extremely challenging without these.
If you are aware of and reference test vector sources for NDR encoding please let me know by raising an issue with the details. Thanks!