# Go Dependency Licenses

This project uses a number of dependencies, in accordance with their own
license terms. These dependencies are managed via the `go.mod` and
`go.sum` files, and included in the source tarball.

The dependencies and their licenses are as follows:

{{ range . }}

## {{ .Name }}

**License:** {{ .LicenseName }}

```
{{ .LicenseText }}
```
{{ end }}
