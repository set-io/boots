package machine

func GdtEntry(flags uint16, base uint32, limit uint32) uint64 {
	return (uint64(base)&0xFF000000)<<(56-24) |
		(uint64(flags)&0x0000F0FF)<<40 |
		(uint64(limit)&0x000F0000)<<(48-16) |
		(uint64(base)&0x00FFFFFF)<<16 |
		(uint64(limit) & 0x0000FFFF)
}

func getBase(entry uint64) uint64 {
	return ((entry & 0xFF00000000000000) >> 32) | ((entry & 0x000000FF00000000) >> 16) | (entry&0x00000000FFFF0000)>>16
}

func getG(entry uint64) uint8 {
	return uint8((entry & 0x0080000000000000) >> 55)
}

func getDB(entry uint64) uint8 {
	return uint8((entry & 0x0040000000000000) >> 54)
}

func getL(entry uint64) uint8 {
	return uint8((entry & 0x0020000000000000) >> 53)
}

func getAVL(entry uint64) uint8 {
	return uint8((entry & 0x0010000000000000) >> 52)
}

func getP(entry uint64) uint8 {
	return uint8((entry & 0x0000800000000000) >> 47)
}

func getDPL(entry uint64) uint8 {
	return uint8((entry & 0x0000600000000000) >> 45)
}

func getS(entry uint64) uint8 {
	return uint8((entry & 0x0000100000000000) >> 44)
}

func getType(entry uint64) uint8 {
	return uint8((entry & 0x00000F0000000000) >> 40)
}

func getLimit(entry uint64) uint32 {
	l := uint32(((((entry) & 0x000F000000000000) >> 32) | ((entry) & 0x000000000000FFFF)))
	g := getG(entry)

	switch g {
	case 0:
		return l
	default:
		return (l << 12) | 0xFFFF
	}
}

func SegmentFromGDT(entry uint64, tableIndex uint8) Segment {
	var unused uint8

	u := getP(entry)

	switch u {
	case 0:
		unused = 1
	default:
		unused = 0
	}

	return Segment{
		Base:     getBase(entry),
		Limit:    getLimit(entry),
		Selector: uint16(tableIndex) * 8,
		Typ:      getType(entry),
		Present:  getP(entry),
		DPL:      getDPL(entry),
		DB:       getDB(entry),
		S:        getS(entry),
		L:        getL(entry),
		G:        getG(entry),
		AVL:      getAVL(entry),
		Unusable: unused,
	}
}
