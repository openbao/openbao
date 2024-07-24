module github.com/openbao/openbao/api/auth/approle/v2

go 1.16

replace github.com/openbao/openbao/api/v2 => ../../

require github.com/openbao/openbao/api/v2 v2.0.1

retract v2.0.0
