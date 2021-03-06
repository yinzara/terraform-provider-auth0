module github.com/terraform-providers/terraform-provider-auth0

go 1.13

replace gopkg.in/auth0.v4 => gopkg.in/yinzara/auth0.v4 v4.0.3-hook-secrets-2

require (
	github.com/hashicorp/go-multierror v1.0.0
	github.com/hashicorp/terraform-plugin-sdk v1.8.0
	gopkg.in/auth0.v4 v4.0.2
)
