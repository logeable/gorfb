package rfb

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
	stInvalid SecurityType = iota
	stNone
	stVNCAuthentication
)

type SecurityTypeResult uint32

/*
	+--------------+--------------+-------------+
	| No. of bytes | Type [Value] | Description |
	+--------------+--------------+-------------+
	| 4            | U32          | status:     |
	|              | 0            | OK          |
	|              | 1            | failed      |
	+--------------+--------------+-------------+
*/
const (
	strOk SecurityTypeResult = iota
	strFailed
)
