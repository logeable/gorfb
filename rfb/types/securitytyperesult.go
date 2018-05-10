package types

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
	STROk SecurityTypeResult = iota
	STRFailed
)
