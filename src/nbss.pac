%include smb.pac


enum NetBIOS_Message_Types {
	NETBIOS_SSN_MSG = 0x0,
	NETBIOS_DGM_DIRECT_UNIQUE = 0x10,
	NETBIOS_DGM_DIRECT_GROUP = 0x11,
	NETBIOS_DGM_BROADCAST = 0x12,
	NETBIOS_DGM_ERROR = 0x13,
	NETBIOS_DGG_QUERY_REQ = 0x14,
	NETBIOS_DGM_POS_RESP = 0x15,
	NETBIOS_DGM_NEG_RESP = 0x16,
	NETBIOS_SSN_REQ = 0x81,
	NETBIOS_SSN_POS_RESP = 0x82,
	NETBIOS_SSN_NEG_RESP = 0x83,
	NETBIOS_SSN_RETARG_RESP = 0x84,
	NETBIOS_SSN_KEEP_ALIVE = 0x85,
};

type NetBIOS_Header = record {
	type     : uint8;
	flags    : uint8;
	length   : uint16;
	data     : case type of {
		NETBIOS_SSN_MSG      -> ssn_msg      : NetBIOS_session_message(self);
		NETBIOS_SSN_REQ      -> ssn_req      : NetBIOS_session_request(self);
		NETBIOS_SSN_POS_RESP -> ssn_pos_resp : NetBIOS_session_pos_response(self);
 		default              -> nothing      : empty;
	};	
};


type NetBIOS_session_message(nb_header: NetBIOS_Header) = record {
	
};

type NetBIOS_Session_Service = record {
	type_and_length  : uint32;
	
} &let {
	message_type = (type_and_length >> 24) & 0xf;
	message_length = type_and_length & 0xfff;
} &byteorder = bigendian;
