package messages

type SecurityType byte

/*
	+--------+--------------------+
	| Number | Name               |
	+--------+--------------------+
	| 0      | Invalid            |
	| 1      | None               |
	| 2      | VNC Authentication |
	+--------+--------------------+
*/
const (
	STInvalid SecurityType = iota
	STNone
	STVNCAuthentication
)
