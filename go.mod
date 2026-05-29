module github.com/rwinkhart/rcw

go 1.26.3

require (
	github.com/Microsoft/go-winio v0.6.2
	github.com/rwinkhart/go-boilerplate v0.3.1
	github.com/rwinkhart/peercred-mini v0.1.4
	golang.org/x/crypto v0.52.0
	golang.org/x/sys v0.45.0
)

require golang.org/x/term v0.43.0 // indirect

replace golang.org/x/sys => github.com/rwinkhart/sys v0.45.0

replace github.com/Microsoft/go-winio => github.com/rwinkhart/go-winio v0.1.1
