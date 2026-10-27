module github.com/rwinkhart/rcw

go 1.27.3

require (
	github.com/Microsoft/go-winio v0.6.4
	github.com/rwinkhart/go-boilerplate v0.4.0
	github.com/rwinkhart/peercred-mini v0.1.6
	golang.org/x/crypto v0.58.0
	golang.org/x/sys v0.49.0
)

require golang.org/x/term v0.47.0 // indirect

replace golang.org/x/sys => github.com/rwinkhart/sys v0.49.0

replace github.com/Microsoft/go-winio => github.com/rwinkhart/go-winio v0.6.4
