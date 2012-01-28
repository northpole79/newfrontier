# Documentation for SMB2 protocol from here: 
#     http://msdn.microsoft.com/en-us/library/cc246497(v=PROT.13).aspx

enum smb2_commands {
	SMB2_NEGOTIATE_PROTOCOL = 0,
	SMB2_SESSION_SETUP      = 1,
	SMB2_LOGOFF             = 2,
	SMB2_TREE_CONNECT       = 3,
	SMB2_TREE_DISCONNECT    = 4,
	SMB2_CREATE             = 5,
	SMB2_CLOSE              = 6,
	SMB2_FLUSH              = 7,
	SMB2_READ               = 8,
	SMB2_WRITE              = 9,
	SMB2_LOCK               = 10,
	SMB2_IOCTL              = 11,
	SMB2_CANCEL             = 12,
	SMB2_ECHO               = 13,
	SMB2_QUERY_DIRECTORY    = 14,
	SMB2_CHANGE_NOTIFY      = 15,
	SMB2_QUERY_INFO         = 16,
	SMB2_SET_INFO           = 17,
	SMB2_OPLOCK_BREAK       = 18,
};

type SMB2_PDU(is_orig: bool) = record {
	header      : SMB2_Header;
	message     : SMB2_Message(is_orig, header);
} &byteorder = littleendian;

type SMB2_Message(is_orig: bool, header: SMB2_Header) = case is_orig of {
	true	->	request :	SMB2_Message_Request(header);
	false	->	response :	SMB2_Message_Response(header);
} &byteorder = littleendian;

type SMB2_Message_Request(header: SMB2_Header) = case header.command of {
	SMB2_NEGOTIATE_PROTOCOL -> negotiate_protocol  : SMB2_negotiate_request(header);
	SMB2_SESSION_SETUP      -> session_setup       : SMB2_session_setup_request(header);
	SMB2_TREE_CONNECT       -> tree_connect        : SMB2_tree_connect_request(header);
	SMB2_TREE_DISCONNECT    -> tree_disconnect     : SMB2_tree_disconnect_request(header);
	SMB2_CREATE             -> create              : SMB2_create_request(header);
	SMB2_CLOSE              -> close               : SMB2_close_request(header);
	SMB2_FLUSH              -> flush               : SMB2_flush_request(header);
	SMB2_READ               -> read                : SMB2_read_request(header);
	SMB2_WRITE              -> write               : SMB2_write_request(header);
	SMB2_LOCK               -> lock                : SMB2_lock_request(header);
	SMB2_IOCTL              -> ioctl               : SMB2_ioctl_request(header);
	SMB2_CANCEL             -> cancel              : SMB2_cancel_request(header);
	SMB2_ECHO               -> echo                : SMB2_echo_request(header);
	SMB2_QUERY_DIRECTORY    -> query_directory     : SMB2_query_directory_request(header);
	SMB2_CHANGE_NOTIFY      -> change_notify       : SMB2_change_notify_request(header);
	SMB2_QUERY_INFO         -> query_info          : SMB2_query_info_request(header);
	SMB2_SET_INFO           -> set_info            : SMB2_set_info_request(header);
	SMB2_OPLOCK_BREAK       -> oplock_break        : SMB2_oplock_break(header);
	
	default                 -> unknown_msg         : empty; # TODO: do something different here!
} &byteorder = littleendian;

type SMB2_Message_Response(header: SMB2_Header) = case header.command of {
	SMB2_NEGOTIATE_PROTOCOL -> negotiate_protocol  : SMB2_negotiate_response(header);
	SMB2_SESSION_SETUP      -> session_setup       : SMB2_session_setup_response(header);
	SMB2_TREE_CONNECT       -> tree_connect        : SMB2_tree_connect_response(header);
	SMB2_TREE_DISCONNECT    -> tree_disconnect     : SMB2_tree_disconnect_response(header);
	SMB2_CREATE             -> create              : SMB2_create_response(header);
	SMB2_CLOSE              -> close               : SMB2_close_response(header);
	SMB2_FLUSH              -> flush               : SMB2_flush_response(header);
	SMB2_READ               -> read                : SMB2_read_response(header);
	SMB2_WRITE              -> write               : SMB2_write_response(header);
	SMB2_LOCK               -> lock                : SMB2_lock_response(header);
	SMB2_IOCTL              -> ioctl               : SMB2_ioctl_response(header);
	SMB2_ECHO               -> echo                : SMB2_echo_response(header);
	SMB2_QUERY_DIRECTORY    -> query_directory     : SMB2_query_directory_response(header);
	SMB2_CHANGE_NOTIFY      -> change_notify       : SMB2_change_notify_response(header);
	SMB2_QUERY_INFO         -> query_info          : SMB2_query_info_response(header);
	SMB2_SET_INFO           -> set_info            : SMB2_set_info_response(header);
	SMB2_OPLOCK_BREAK       -> oplock_break        : SMB2_oplock_break(header);

	default                 -> unknown_msg         : empty; # TODO: do something different here!
} &byteorder = littleendian;

type SMB2_guid = bytestring &length = 16;

type SMB2_Header = record {
	head_length   : uint16;
	credit_charge : uint16;
	status        : uint32;
	command       : uint16;
	credits       : uint16;
	flags         : uint32;
	next_command  : uint32;
	message_id    : bytestring &length = 8;
	process_id    : uint32;
	tree_id       : uint32;
	session_id    : bytestring &length = 8;
	signature     : bytestring &length = 16;
} &let {
	response = (flags >> 24) & 1;
	async    = (flags >> 25) & 1;
	related  = (flags >> 26) & 1;
	msigned  = (flags >> 27) & 1;
	dfs      = (flags) & 1;
} &byteorder = littleendian;

type SMB2_security = record {
	buffer_offset     : uint16;
	buffer_len        : uint16;
	# TODO: handle previous session IDs
	sec_buffer        : bytestring &length = buffer_len;
} &byteorder = littleendian;

type SMB2_timestamp = record {
	lowbits           : uint32;
	highbits          : uint32;
} &byteorder = littleendian;

type SMB2_file_id = record {
	persistent        : bytestring &length = 8;
	_volatile         : bytestring &length = 8;
};

type SMB2_lock = record {
	# TODO: 64-bit filesystem problems
	offset            : uint32;
	offset2           : uint32;
	len               : uint32;
	len2              : uint32;
	flags             : uint32;
};

type SMB2_string(len: int) = record {
	# divide by 2 because all SMB2 strings are 16-bit Unicode
	# but the length is given in bytes
	s                 : uint16[len/2];
};

type SMB2_File_Notify_Information = record {
	next_entry_offset : uint32;
	action            : uint32;
	filename_len      : uint32;
	filename          : SMB2_string(filename_len);
};

type SMB2_create_context(len: int) = record {
	next              : uint32;
	name_offset       : uint16;
	name_len          : uint16;
	reserved          : uint16;
	data_offset       : uint16;
	data_len          : uint16;
	pad               : padding[name_offset - offsetof(data_len)+2];
	name              : SMB2_string(name_len);
	pad2              : padding[data_offset - offsetof(name)+name_len];
	data              : SMB2_string(data_len);
	next_context      : case next of {
		0       -> done    : empty;
		default -> context : SMB2_create_context(len-offsetof(next_context));
	};
};

type SMB2_symlink_error(byte_count: uint32) = record {
	sym_link_length   : uint32;
	sym_link_err_tag  : uint32;
	reparse_tag       : uint32;
	reparse_data_len  : uint16;
	unparsed_path_len : uint16;
	sub_name_offset   : uint16;
	sub_name_length   : uint16;
	print_name_offset : uint16;
	print_name_length : uint16;
	flags             : uint32;
	path_buffer       : bytestring &length = sub_name_length+print_name_length;
} &let {
	absolute_target_path  = (flags == 0x00000000);
	symlink_flag_relative = (flags == 0x00000001);
} &byteorder = littleendian;

type SMB2_error_data(byte_count: uint32) = case byte_count of {
	0       -> empty: uint8;
	default -> error: SMB2_symlink_error(byte_count);
} &byteorder = littleendian;

type SMB2_error_response = record {
	structure_size    : uint16;
	reserved          : padding[2];
	byte_count        : uint32;
	error_data        : SMB2_error_data(byte_count);
} &byteorder = littleendian;

type SMB2_negotiate_request(header: SMB2_Header) = record {
	structure_size    : uint16;          # client MUST set this to 36
	dialect_count     : uint16;          # must be > 0
	security_mode     : uint16;          # there is a list of required modes
	reserved          : padding[2];      # must be set to 0
	capabilities      : uint32;          # must be set to 0
	client_guid       : SMB2_guid;       # guid if client implements SMB 2.1 dialect, otherwise set to 0
	client_start_time : SMB2_timestamp;  # must be set to 0
	dialects          : uint16[dialect_count];
} &byteorder = littleendian;

type SMB2_negotiate_response(header: SMB2_Header) = record {
	structure_size    : uint16;
	security_mode     : uint16;
	dialect_revision  : uint16;
	reserved          : padding[2];
	server_guid       : SMB2_guid;
	capabilities      : uint32;
	max_transact_size : uint32;
	max_read_size     : uint32;
	max_write_size    : uint32;
	system_time       : SMB2_timestamp;
	server_start_time : SMB2_timestamp;
	security          : SMB2_security;
} &byteorder = littleendian; # &length = structure_size + security.buffer_len - 1;

type SMB2_session_setup_request(header: SMB2_Header) = record {
	structure_size    : uint16;
	vc_number         : uint8;
	security_mode     : uint8;
	capabilities      : uint32;
	channel           : uint32;
	security          : SMB2_security;
} &byteorder = littleendian; # &length = structure_size+security.buffer_len - 1;

type SMB2_session_setup_response(header: SMB2_Header) = record {
	structure_size    : uint16;
	session_flags     : uint16;
	security          : SMB2_security;
} &let {
	guest     = ((session_flags & 0xf) == 1);
	anonymous = ((session_flags & 0xf) == 2);
} &byteorder = littleendian; # &length = structure_size+security.buffer_len - 1;

type SMB2_logoff_request(header: SMB2_Header) = record {
	structure_size    : uint16;
	reserved          : uint16;
};

type SMB2_logoff_response(header: SMB2_Header) = record {
	structure_size    : uint16;
	reserved          : uint16;
};

type SMB2_tree_connect_request(header: SMB2_Header) = record {
	structure_size    : uint16;
	reserved          : padding[2];
	path_offset       : uint16;
	path_length       : uint16;
	buffer            : bytestring &length = path_length;
} &byteorder = littleendian;

type SMB2_tree_connect_response(header: SMB2_Header) = record {
	structure_size    : uint16;
	share_type        : uint8;
	reserved          : padding[1];
	share_flags       : uint32;
	capabilities      : uint32;
	maximal_access    : uint32;
} &byteorder = littleendian;

type SMB2_tree_disconnect_request(header: SMB2_Header) = record {
	structure_size    : uint16;
	reserved          : uint16;
};

type SMB2_tree_disconnect_response(header: SMB2_Header) = record {
	structure_size    : uint16;
	reserved          : uint16;
};

type SMB2_create_request(header: SMB2_Header) = record {
	structure_size      : uint16;
	sec_flags_reserved  : uint8;  # ignored
	oplock              : uint8;
	impersonation_level : uint32;
	flags               : bytestring &length=8; # ignored
	reserved            : bytestring &length=8; # ignored
	access_mask         : uint32;
	file_attrs          : uint32;
	share_access        : uint32;
	disposition         : uint32;
	create_options      : uint32;
	filename_offset     : uint16;
	filename_len        : uint16;
	context_offset      : uint32;
	context_len         : uint32;
	pad                 : padding to filename_offset - header.head_length;
	filename            : SMB2_string(filename_len);
	pad2                : padding to context_offset - header.head_length;
	create_context      : SMB2_create_context(context_len);
};

type SMB2_create_response(header: SMB2_Header) = record {
	structure_size      : uint16;
	oplock              : uint8;
	reserved            : uint8;
	create_action       : uint32;
	creation_time       : SMB2_timestamp;
	last_access_time    : SMB2_timestamp;
	last_write_time     : SMB2_timestamp;
	change_time         : SMB2_timestamp;
	alloc_size          : uint32;
	alloc_size2         : uint32;
	eof                 : uint32;
	eof2                : uint32;
	file_attrs          : uint32;
	reserved2           : uint32;
	file_id             : SMB2_file_id;
	context_offset      : uint32;
	context_len         : uint32;
	pad2                : padding to context_offset - header.head_length;
	create_context      : SMB2_create_context(context_len);
};

type SMB2_close_request(header: SMB2_Header) = record {
	structure_size      : uint16;
	flags               : uint16;
	reserved            : uint32;
	file_id             : SMB2_file_id;
};

type SMB2_close_response(header: SMB2_Header) = record {
	structure_size      : uint16;
	flags               : uint16;
	reserved            : uint32;
	
	creation_time       : SMB2_timestamp;
	last_access_time    : SMB2_timestamp;
	last_write_time     : SMB2_timestamp;
	change_time         : SMB2_timestamp;
	# TODO: handle 64-bit filesystem!
	alloc_size          : uint32;
	alloc_size2         : uint32;
	eof                 : uint32;
	eof2                : uint32;
	file_attrs          : uint32;
};

type SMB2_flush_request(header: SMB2_Header) = record {
	structure_size    : uint16;
	reserved1         : uint16;
	reserved2         : uint32;
	file_id           : SMB2_file_id;
};

type SMB2_flush_response(header: SMB2_Header) = record {
	structure_size    : uint16;
	reserved1         : uint16;
};

type SMB2_read_request(header: SMB2_Header) = record {
	structure_size    : uint16;
	pad               : uint8;
	reserved          : uint8;
	length            : uint32;
	# TODO: Another 64-bit filesystem issue!
	offset            : uint32;
	offset2           : uint32;
	file_id           : SMB2_file_id;
	minimum_count     : uint32;
	channel           : uint32; # ignore
	remaining_bytes   : uint32;
	# Everything below should just be 0 and unused currently.
	#channel_info_offset : uint16;
	#channel_info_len  : uint16;
	#pad               : padding to channel_info_offset - header.head_length;
	#buffer            : bytestring &length = channel_info_len;
	#This is to skip over the bytes
	trash             : bytestring &length = 33;
};

type SMB2_read_response(header: SMB2_Header) = record {
	structure_size    : uint16;
	data_offset       : uint8;
	reserved          : uint8;
	data_len          : uint32;
	data_remaining    : uint32; # ignore
	reserved2         : uint32;
	pad               : padding to data_offset - header.head_length;
	data              : bytestring &length = data_len;
};

type SMB2_write_request(header: SMB2_Header) = record {
	structure_size    : uint16;
	data_offset       : uint16;
	data_len          : uint32;
	# TODO: more 64-bit filesystem trouble
	offset            : uint32;
	offset2           : uint32;
	file_id           : SMB2_file_id;
	channel           : uint32; # ignore
	data_remaining    : uint32;
	channel_info_offset : uint16; # ignore
	channel_info_len  : uint16; # ignore
	flags             : uint32;
	pad               : padding to data_offset - header.head_length;
	data              : bytestring &length = data_len;
};

type SMB2_write_response(header: SMB2_Header) = record {
	structure_size    : uint16;
	reserved          : uint16;   # ignore
	byte_count        : uint32;
	remaining         : uint32;   # ignore
	channel_info_offset : uint16; # ignore
	channel_info_len  : uint16;   # ignore 
};

type SMB2_lock_request(header: SMB2_Header) = record {
	structure_size    : uint16;
	lock_count        : uint16;
	lock_seq          : uint32;
	file_id           : SMB2_file_id;
	locks             : SMB2_lock[lock_count];
};

type SMB2_lock_response(header: SMB2_Header) = record {
	structure_size    : uint16;
	reserved          : uint16; # ignore
};

type SMB2_ioctl_request(header: SMB2_Header) = record {
	structure_size    : uint16;
	reserved          : uint16;
	ctl_code          : uint32;
	file_id           : SMB2_file_id;
	input_offset      : uint32;
	input_count       : uint32;
	max_input_resp    : uint32;
	output_offset     : uint32;
	output_count      : uint32;
	max_output_resp   : uint32;
	flags             : uint32;
	reserved2         : uint32;
	pad               : padding to input_offset - header.head_length;
	input_buffer      : bytestring &length = input_count;
	pad2              : padding to output_offset - header.head_length;
	output_buffer     : bytestring &length=output_count;
};

type SMB2_ioctl_response(header: SMB2_Header) = record {
	structure_size    : uint16;
	reserved          : uint16;
	ctl_code          : uint32;
	file_id           : SMB2_file_id;
	input_offset      : uint32;
	input_count       : uint32;
	output_offset     : uint32;
	output_count      : uint32;
	flags             : uint32;
	reserved2         : uint32;
	pad               : padding to input_offset - header.head_length;
	input_buffer      : bytestring &length=input_count;
	pad2              : padding to output_offset - header.head_length;
	output_buffer     : bytestring &length=output_count;
};

type SMB2_cancel_request(header: SMB2_Header) = record {
	structure_size    : uint16;
	reserved          : uint16;
};

type SMB2_echo_request(header: SMB2_Header) = record {
	structure_size    : uint16;
	reserved          : uint16;
};

type SMB2_echo_response(header: SMB2_Header) = record {
	structure_size    : uint16;
	reserved          : uint16;
};

type SMB2_query_directory_request(header: SMB2_Header) = record {
	structure_size    : uint16;
	_class            : uint8;
	flags             : uint8;
	file_index        : uint32;
	file_id           : SMB2_file_id;
	file_name_offset  : uint16;
	file_name_len     : uint16;
	output_buffer_len : uint32;
	pad               : padding to file_name_offset - header.head_length;
	file_name         : bytestring &length = file_name_len;
};

type SMB2_query_directory_response(header: SMB2_Header) = record {
	structure_size    : uint16;
	buffer_offset     : uint16;
	buffer_len        : uint32;
	pad               : padding to buffer_offset - header.head_length;
	buffer            : bytestring &length = buffer_len;
};

type SMB2_change_notify_request(header: SMB2_Header) = record {
	structure_size    : uint16;
	flags             : uint16;
	output_buffer_len : uint32;
	file_id           : SMB2_file_id;
	completion_filter : uint32;
	reserved          : uint32;
};

type SMB2_change_notify_response(header: SMB2_Header) = record {
	structure_size       : uint16;
	output_buffer_offset : uint16;
	output_buffer_len    : uint32;
	pad                  : padding to output_buffer_offset - header.head_length;
	buffer               : SMB2_File_Notify_Information[] &length = output_buffer_len;
};

type SMB2_query_info_request(header: SMB2_Header) = record {
	structure_size      : uint16;
	info_type           : uint8;
	file_info_class     : uint8;
	output_buffer_len   : uint32;
	input_buffer_offset : uint16;
	reserved            : uint16;
	input_buffer_len    : uint32;
	additional_info     : uint32;
	flags               : uint32;
	file_id             : SMB2_file_id;
	pad                 : padding to input_buffer_offset - header.head_length;
	buffer              : bytestring &length = input_buffer_len;
};

type SMB2_query_info_response(header: SMB2_Header) = record {
	structure_size      : uint16;
	buffer_offset       : uint16;
	buffer_len          : uint32;
	pad                 : padding to buffer_offset - header.head_length;
	# TODO: a new structure needs to be created for this.
	buffer              : bytestring &length = buffer_len;
};

type SMB2_set_info_request(header: SMB2_Header) = record {
	structure_size      : uint16;
	info_type           : uint8;
	file_info_class     : uint8;
	buffer_len          : uint32;
	buffer_offset       : uint16;
	reserved            : uint16;
	additional_info     : uint32;
	file_id             : SMB2_file_id;
	pad                 : padding to buffer_offset - header.head_length;
	# TODO: a new structure needs to be created for this.
	buffer              : bytestring &length = buffer_len;
};

type SMB2_set_info_response(header: SMB2_Header) = record {
	structure_size      : uint16;
};

type SMB2_oplock_break(header: SMB2_Header) = record {
	structure_size      : uint16;
	oplock_level        : uint8;
	reserved            : uint8;
	reserved2           : uint32;
	file_id             : SMB2_file_id;
};
