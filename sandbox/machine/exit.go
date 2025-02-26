package machine

//go:generate stringer -type=Exit
type Exit uint

const (
	EXITUNKNOWN       Exit = 0
	EXITEXCEPTION     Exit = 1
	EXITIO            Exit = 2
	EXITHYPERCALL     Exit = 3
	EXITDEBUG         Exit = 4
	EXITHLT           Exit = 5
	EXITMMIO          Exit = 6
	EXITIRQWINDOWOPEN Exit = 7
	EXITSHUTDOWN      Exit = 8
	EXITFAILENTRY     Exit = 9
	EXITINTR          Exit = 10
	EXITSETTPR        Exit = 11
	EXITTPRACCESS     Exit = 12
	EXITS390SIEIC     Exit = 13
	EXITS390RESET     Exit = 14
	EXITDCR           Exit = 15
	EXITNMI           Exit = 16
	EXITINTERNALERROR Exit = 17

	EXITIOIN  = 0
	EXITIOOUT = 1
)
