

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

type NetBIOS_PDU(is_orig: bool) = record {
	type     : uint8;
	#flags    : uint8;
	#length   : uint16;
	len24    : uint24;
	data     : case type of {
		NETBIOS_SSN_MSG      -> ssn_msg      : NetBIOS_session_message(this, is_orig);
		NETBIOS_SSN_REQ      -> ssn_req      : NetBIOS_session_request(this, is_orig);
		NETBIOS_SSN_POS_RESP -> ssn_pos_resp : NetBIOS_session_pos_response(this, is_orig);
 		default              -> nothing      : empty &restofdata;
	};	
} &let {
	len : uint32 = to_int(len24);
} &byteorder = bigendian &length=len+4;

type NetBIOS_session_message(header: NetBIOS_PDU, is_orig: bool) = record {
	smb   : SMB_PDU(is_orig);
} &byteorder = bigendian;

type NetBIOS_session_request(header: NetBIOS_PDU, is_orig: bool) = record {
};

type NetBIOS_session_pos_response(header: NetBIOS_PDU, is_orig: bool) = record {	
};

