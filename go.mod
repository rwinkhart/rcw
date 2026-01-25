module github.com/rwinkhart/rcw

go 1.25.6

require (
	github.com/Microsoft/go-winio v0.6.2
	github.com/rwinkhart/go-boilerplate v0.2.2
	github.com/rwinkhart/peercred-mini v0.1.2
	golang.org/x/crypto v0.47.0
	golang.org/x/sys v0.40.0
)

require golang.org/x/term v0.39.0 // indirect

replace golang.org/x/sys => github.com/rwinkhart/sys v0.40.0

replace github.com/Microsoft/go-winio => github.com/rwinkhart/go-winio v0.1.0
