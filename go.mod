module github.com/rwinkhart/rcw

go 1.25.7

require (
	github.com/Microsoft/go-winio v0.6.2
	github.com/rwinkhart/go-boilerplate v0.2.3-0.20260210031547-48e6abea8b2f
	github.com/rwinkhart/peercred-mini v0.1.3
	golang.org/x/crypto v0.48.0
	golang.org/x/sys v0.41.0
)

require golang.org/x/term v0.40.0 // indirect

replace golang.org/x/sys => github.com/rwinkhart/sys v0.41.0

replace github.com/Microsoft/go-winio => github.com/rwinkhart/go-winio v0.1.1
