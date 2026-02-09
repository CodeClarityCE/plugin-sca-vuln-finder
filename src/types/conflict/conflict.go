package conflict

type ResolveWinner string

const (
	NVD  ResolveWinner = "NVD"
	OSV  ResolveWinner = "OSV"
	GCVE ResolveWinner = "GCVE"
	NONE ResolveWinner = "NONE"
)

type ConflictFlag string

const (
	MATCH_CORRECT            ConflictFlag = "MATCH_CORRECT"
	MATCH_INCORRECT          ConflictFlag = "MATCH_INCORRECT"
	MATCH_POSSIBLE_INCORRECT ConflictFlag = "MATCH_POSSIBLE_INCORRECT"
	MATCH_NO_CONFLICT        ConflictFlag = "NO_CONFLICT"
)
