type NetBIOS_Session_Service = record {
	type_and_length  : uint32;
} &let {
	message_type = (type_and_length >> 24) & 0xf;
	message_length = type_and_length & 0xfff;
} &byteorder = bigendian;
