
extern void ndpiInitialize();
int original_main();

/*
func  ClassifyFlow(flow *types.Flow) (types.Protocols) {
	packets := flow.GetPackets()
	if len(packets) > 0 {
		ndpiFlow := (*wrapper.provider).ndpiAllocFlow(packets[0])
		defer (*wrapper.provider).ndpiFreeFlow(ndpiFlow)
		for _, ppacket := range packets {
			ndpiProto := (*wrapper.provider).ndpiPacketProcess(ppacket, ndpiFlow)
			if proto, found := ndpiCodeToProtocol[uint32(ndpiProto)]; found {
				return proto, nil
			} else if ndpiProto < 0 {
				switch ndpiProto {
				case -10:
					return types.Unknown, errors.New("nDPI wrapper does not support IPv6")
				case -11:
					return types.Unknown, errors.New("Received fragmented packet")
				case -12:
					return types.Unknown, errors.New("Error creating nDPI flow")
				default:
					return types.Unknown, errors.New("nDPI unknown error")
				}
			}
		}
	}
	return types.Unknown, nil
}*/