# $Id$
#
# CIFS/SMB

# TODO:
# - Built support for unicode strings
# - Unicode as an implicit attribute (as byteorder)
# - &truncation_ok attribute for the last field of a record to deal with partial data

enum TransactionType {
	SMB_MAILSLOT_BROWSE, # \MAILSLOT\BROWSE - MS Browse Protocol
	SMB_MAILSLOT_LANMAN, # \MAILSLOT\LANMAN - deprecated cmds
	SMB_PIPE, # \PIPE\* named pipes?
	SMB_RAP, # \PIPE\LANMAN - remote administration protocol
	SMB_UNKNOWN, # theres probably lots of these
};

enum SMB_Command {
	SMB_COM_CREATE_DIRECTORY = 0x00,
	SMB_COM_DELETE_DIRECTORY = 0x01,
	SMB_COM_OPEN = 0x02,
	SMB_COM_CREATE = 0x03,
	SMB_COM_CLOSE = 0x04,
	SMB_COM_FLUSH = 0x05,
	SMB_COM_DELETE = 0x06,
	SMB_COM_RENAME = 0x07,
	SMB_COM_QUERY_INFORMATION = 0x08,
	SMB_COM_SET_INFORMATION = 0x09,
	SMB_COM_READ = 0x0A,
	SMB_COM_WRITE = 0x0B,
	SMB_COM_LOCK_BYTE_RANGE = 0x0C,
	SMB_COM_UNLOCK_BYTE_RANGE = 0x0D,
	SMB_COM_CREATE_TEMPORARY = 0x0E,
	SMB_COM_CREATE_NEW = 0x0F,
	SMB_COM_CHECK_DIRECTORY = 0x10,
	SMB_COM_PROCESS_EXIT = 0x11,
	SMB_COM_SEEK = 0x12,
	SMB_COM_LOCK_AND_READ = 0x13,
	SMB_COM_WRITE_AND_UNLOCK = 0x14,
	SMB_COM_READ_RAW = 0x1A,
	SMB_COM_READ_MPX = 0x1B,
	SMB_COM_READ_MPX_SECONDARY = 0x1C,
	SMB_COM_WRITE_RAW = 0x1D,
	SMB_COM_WRITE_MPX = 0x1E,
	SMB_COM_WRITE_MPX_SECONDARY = 0x1F,
	SMB_COM_WRITE_COMPLETE = 0x20,
	SMB_COM_QUERY_SERVER = 0x21,
	SMB_COM_SET_INFORMATION2 = 0x22,
	SMB_COM_QUERY_INFORMATION2 = 0x23,
	SMB_COM_LOCKING_ANDX = 0x24,
	SMB_COM_TRANSACTION = 0x25,
	SMB_COM_TRANSACTION_SECONDARY = 0x26,
	SMB_COM_IOCTL = 0x27,
	SMB_COM_IOCTL_SECONDARY = 0x28,
	SMB_COM_COPY = 0x29,
	SMB_COM_MOVE = 0x2A,
	SMB_COM_ECHO = 0x2B,
	SMB_COM_WRITE_AND_CLOSE = 0x2C,
	SMB_COM_OPEN_ANDX = 0x2D,
	SMB_COM_READ_ANDX = 0x2E,
	SMB_COM_WRITE_ANDX = 0x2F,
	SMB_COM_NEW_FILE_SIZE = 0x30,
	SMB_COM_CLOSE_AND_TREE_DISC = 0x31,
	SMB_COM_TRANSACTION2 = 0x32,
	SMB_COM_TRANSACTION2_SECONDARY = 0x33,
	SMB_COM_FIND_CLOSE2 = 0x34,
	SMB_COM_FIND_NOTIFY_CLOSE = 0x35,
	
	SMB_COM_TREE_CONNECT = 0x70,
	SMB_COM_TREE_DISCONNECT = 0x71,
	SMB_COM_NEGOTIATE = 0x72,
	SMB_COM_SESSION_SETUP_ANDX = 0x73,
	SMB_COM_LOGOFF_ANDX = 0x74,
	SMB_COM_TREE_CONNECT_ANDX = 0x75,
	SMB_COM_QUERY_INFORMATION_DISK = 0x80,
	SMB_COM_SEARCH = 0x81,
	SMB_COM_FIND = 0x82,
	SMB_COM_FIND_UNIQUE = 0x83,
	SMB_COM_FIND_CLOSE = 0x84,
	SMB_COM_NT_TRANSACT = 0xA0,
	SMB_COM_NT_TRANSACT_SECONDARY = 0xA1,
	SMB_COM_NT_CREATE_ANDX = 0xA2,
	SMB_COM_NT_CANCEL = 0xA4,
	SMB_COM_NT_RENAME = 0xA5,
	SMB_COM_OPEN_PRINT_FILE = 0xC0,
	SMB_COM_WRITE_PRINT_FILE = 0xC1,
	SMB_COM_CLOSE_PRINT_FILE = 0xC2,
	SMB_COM_GET_PRINT_QUEUE = 0xC3,
	SMB_COM_READ_BULK = 0xD8,
	SMB_COM_WRITE_BULK = 0xD9,
	SMB_COM_WRITE_BULK_DATA = 0xDA,	
};

function extract_string(s: SMB_string) : const_bytestring
	%{
	int length = 0;

	char* buf;
	const char* sp;

	if( s->val_case_index() == 0 )
		{
		length = s->a()->size();
		buf = new char[ length ];

		for( int i = 0; i < length; i++)
			{
			unsigned char t = (*(s->a()))[i];
			buf[i] = t;
			}
		}
	else
		{
		length = s->u()->s()->size();
		buf = new char[ length ];

		for( int i = 0; i < length; i++)
			{
			unsigned short temp = (*(s->u()->s()))[i];
			buf[i] = temp & 0xff;
			}
		}

	return bytestring((uint8*) buf, length);
	%}

function determine_transaction_type(setup_count: int, name: SMB_string): TransactionType
	%{
	// This logic needs to be verified! the relationship between
	// setup_count and type is very unclear.
	if ( name == NULL )
		return SMB_UNKNOWN;

	if ( bytestring_caseprefix( extract_string(name),
			"\\PIPE\\LANMAN" ) )
		{
		return SMB_RAP;
		}
	else if ( bytestring_caseprefix( extract_string(name),
			"\\MAILSLOT\\LANMAN" ) )
		{
		return SMB_MAILSLOT_LANMAN;
		//return SMB_MAILSLOT_BROWSE;
		}
	else if ( bytestring_caseprefix( extract_string(name),
			"\\MAILSLOT\\NET\\NETLOGON" ) )
		{
		/* Don't really know what to do here, its got a Mailslot
		 * type but its a deprecated packet format that handles
		 * old windows logon
		 */
		return SMB_UNKNOWN;
		}
	else if(setup_count == 2 ||
			bytestring_caseprefix( extract_string(name), "\\PIPE\\" ) )
		{
		return SMB_PIPE;
		}
	else if (setup_count == 3 ||
			bytestring_caseprefix( extract_string(name), "\\MAILSLOT\\" ) )
		{
		return SMB_MAILSLOT_BROWSE;
		}
	else
		return SMB_UNKNOWN;
	%}
	
type SMB_PDU(is_orig: bool) = record {
	nbss        : NetBIOS_Session_Service;
	header      : SMB_Header;
	message     : SMB_Message(is_orig, header);
} &byteorder = littleendian &length = nbss.message_length+4;

type SMB_Message(is_orig: bool, header: SMB_Header) = case is_orig of {
	true    ->  request   : SMB_Message_Request(header);
	false   ->  response  : SMB_Message_Response(header);
};

type SMB_Message_Request(header: SMB_Header) = case header.command of {
	SMB_COM_CREATE_DIRECTORY         -> create_directory       : SMB_create_directory_request(header);
	#SMB_COM_DELETE_DIRECTORY         -> delete_directory       : SMB_delete_directory_request(header);
	#SMB_COM_OPEN                     -> open                   : SMB_open_request(header);
	#SMB_COM_CREATE                   -> create                 : SMB_create_request(header);
	SMB_COM_CLOSE                    -> close                  : SMB_close_request(header);
	#SMB_COM_FLUSH                    -> flush                  : SMB_flush_request(header);
	#SMB_COM_DELETE                   -> delete                 : SMB_delete_request(header);
	#SMB_COM_RENAME                   -> rename                 : SMB_rename_request(header);
	#SMB_COM_QUERY_INFORMATION        -> query_information      : SMB_query_information_request(header);
	#SMB_COM_SET_INFORMATION          -> set_information        : SMB_set_information_request(header);
	#SMB_COM_READ                     -> read                   : SMB_read_request(header);
	#SMB_COM_WRITE                    -> write                  : SMB_write_request(header);
	#SMB_COM_LOCK_BYTE_RANGE          -> lock_byte_range        : SMB_lock_byte_range_request(header);
	#SMB_COM_UNLOCK_BYTE_RANGE        -> unlock_byte_range      : SMB_unlock_byte_range_request(header);
	#SMB_COM_CREATE_TEMPORARY         -> create_temporary       : SMB_create_temporary_request(header);
	#SMB_COM_CREATE_NEW               -> create_new             : SMB_create_new_request(header);
	#SMB_COM_CHECK_DIRECTORY          -> check_directory        : SMB_check_directory_request(header);
	#SMB_COM_PROCESS_EXIT             -> process_exit           : SMB_process_exit_request(header);
	#SMB_COM_SEEK                     -> seek                   : SMB_seek_request(header);
	#SMB_COM_LOCK_AND_READ            -> lock_and_read          : SMB_lock_and_read_request(header);
	#SMB_COM_WRITE_AND_UNLOCK         -> write_and_unlock       : SMB_write_and_unlock_request(header);
	#SMB_COM_READ_RAW                 -> read_raw               : SMB_read_raw_request(header);
	#SMB_COM_READ_MPX                 -> read_mpx               : SMB_read_mpx_request(header);
	#SMB_COM_READ_MPX_SECONDARY       -> read_mpx_secondary     : SMB_read_mpx_secondary_request(header);
	#SMB_COM_WRITE_RAW                -> write_raw              : SMB_write_raw_request(header);
	#SMB_COM_WRITE_MPX                -> write_mpx              : SMB_write_mpx_request(header);
	#SMB_COM_WRITE_MPX_SECONDARY      -> write_mpx_secondary    : SMB_write_mpx_secondary_request(header);
	#SMB_COM_WRITE_COMPLETE           -> write_complete         : SMB_write_complete_request(header);
	#SMB_COM_QUERY_SERVER             -> query_server           : SMB_query_server_request(header);
	#SMB_COM_SET_INFORMATION2         -> set_information2       : SMB_set_information2_request(header);
	#SMB_COM_QUERY_INFORMATION2       -> query_information2     : SMB_query_information2_request(header);
	#SMB_COM_LOCKING_ANDX             -> locking_andx           : SMB_locking_andx_request(header);
	SMB_COM_TRANSACTION              -> transaction            : SMB_transaction_request(header);
	SMB_COM_TRANSACTION_SECONDARY    -> transaction_secondary  : SMB_transaction_secondary_request(header);
	#SMB_COM_IOCTL                    -> ioctl                  : SMB_ioctl_request(header);
	#SMB_COM_IOCTL_SECONDARY          -> ioctl_secondary        : SMB_ioctl_secondary_request(header);
	#SMB_COM_COPY                     -> copy                   : SMB_copy_request(header);
	#SMB_COM_MOVE                     -> move                   : SMB_move_request(header);
	#SMB_COM_ECHO                     -> echo                   : SMB_echo_request(header);
	#SMB_COM_WRITE_AND_CLOSE          -> write_and_close        : SMB_write_and_close_request(header);
	#SMB_COM_OPEN_ANDX                -> open_andx              : SMB_open_andx_request(header);
	SMB_COM_READ_ANDX                -> read_andx              : SMB_read_andx_request(header);
	SMB_COM_WRITE_ANDX               -> write_andx             : SMB_write_andx_request(header);
	#SMB_COM_NEW_FILE_SIZE            -> new_file_size          : SMB_new_file_size_request(header);
	#SMB_COM_CLOSE_AND_TREE_DISC      -> close_and_tree_disc    : SMB_close_and_tree_disc_request(header);
	#SMB_COM_TRANSACTION2             -> transaction2           : SMB_transaction2_request(header);
	#SMB_COM_TRANSACTION2_SECONDARY   -> transaction2_secondary : SMB_transaction2_secondary_request(header);
	#SMB_COM_FIND_CLOSE2              -> find_close2            : SMB_find_close2_request(header);
	#SMB_COM_FIND_NOTIFY_CLOSE        -> find_notify_close      : SMB_find_notify_close_request(header);
	#SMB_COM_TREE_CONNECT             -> tree_connect           : SMB_tree_connect_request(header);
	#SMB_COM_TREE_DISCONNECT          -> tree_disconnect        : SMB_tree_disconnect_request(header);
	SMB_COM_NEGOTIATE                -> negotiate              : SMB_negotiate_request(header);
	#SMB_COM_SESSION_SETUP_ANDX       -> session_setup_andx     : SMB_session_setup_andx_request(header);
	#SMB_COM_LOGOFF_ANDX              -> logoff_andx            : SMB_logoff_andx_request(header);
	SMB_COM_TREE_CONNECT_ANDX        -> tree_connect_andx      : SMB_tree_connect_andx_request(header);
	#SMB_COM_QUERY_INFORMATION_DISK   -> query_information_disk : SMB_query_information_disk_request(header);
	#SMB_COM_SEARCH                   -> search                 : SMB_search_request(header);
	#SMB_COM_FIND                     -> find                   : SMB_find_request(header);
	#SMB_COM_FIND_UNIQUE              -> find_unique            : SMB_find_unique_request(header);
	#SMB_COM_FIND_CLOSE               -> find_close             : SMB_find_close_request(header);
	#SMB_COM_NT_TRANSACT              -> nt_transact            : SMB_nt_transact_request(header);
	#SMB_COM_NT_TRANSACT_SECONDARY    -> nt_transact_secondary  : SMB_nt_transact_secondary_request(header);
	SMB_COM_NT_CREATE_ANDX           -> nt_create_andx         : SMB_nt_create_andx_request(header);
	#SMB_COM_NT_CANCEL                -> nt_cancel              : SMB_nt_cancel_request(header);
	#SMB_COM_NT_RENAME                -> nt_rename              : SMB_nt_rename_request(header);
	#SMB_COM_OPEN_PRINT_FILE          -> open_print_file        : SMB_open_print_file_request(header);
	#SMB_COM_WRITE_PRINT_FILE         -> write_print_file       : SMB_write_print_file_request(header);
	#SMB_COM_CLOSE_PRINT_FILE         -> close_print_file       : SMB_close_print_file_request(header);
	#SMB_COM_GET_PRINT_QUEUE          -> get_print_queue        : SMB_get_print_queue_request(header);
	#SMB_COM_READ_BULK                -> read_bulk              : SMB_read_bulk_request(header);
	#SMB_COM_WRITE_BULK               -> write_bulk             : SMB_write_bulk_request(header);
	#SMB_COM_WRITE_BULK_DATA          -> write_bulk_data        : SMB_write_bulk_data_request(header);
	default                          -> unknown_msg            : empty; # TODO: do something different here!
} &byteorder = littleendian;

type SMB_Message_Response(header: SMB_Header) = case header.command of {
	SMB_COM_CREATE_DIRECTORY         -> create_directory       : SMB_create_directory_response(header);
	#SMB_COM_DELETE_DIRECTORY         -> delete_directory       : SMB_delete_directory_response(header);
	#SMB_COM_OPEN                     -> open                   : SMB_open_response(header);
	#SMB_COM_CREATE                   -> create                 : SMB_create_response(header);
	SMB_COM_CLOSE                    -> close                  : SMB_empty_response(header);
	#SMB_COM_FLUSH                    -> flush                  : SMB_flush_response(header);
	#SMB_COM_DELETE                   -> delete                 : SMB_delete_response(header);
	#SMB_COM_RENAME                   -> rename                 : SMB_rename_response(header);
	#SMB_COM_QUERY_INFORMATION        -> query_information      : SMB_query_information_response(header);
	#SMB_COM_SET_INFORMATION          -> set_information        : SMB_set_information_response(header);
	#SMB_COM_READ                     -> read                   : SMB_read_response(header);
	#SMB_COM_WRITE                    -> write                  : SMB_write_response(header);
	#SMB_COM_LOCK_BYTE_RANGE          -> lock_byte_range        : SMB_lock_byte_range_response(header);
	#SMB_COM_UNLOCK_BYTE_RANGE        -> unlock_byte_range      : SMB_unlock_byte_range_response(header);
	#SMB_COM_CREATE_TEMPORARY         -> create_temporary       : SMB_create_temporary_response(header);
	#SMB_COM_CREATE_NEW               -> create_new             : SMB_create_new_response(header);
	#SMB_COM_CHECK_DIRECTORY          -> check_directory        : SMB_check_directory_response(header);
	#SMB_COM_PROCESS_EXIT             -> process_exit           : SMB_process_exit_response(header);
	#SMB_COM_SEEK                     -> seek                   : SMB_seek_response(header);
	#SMB_COM_LOCK_AND_READ            -> lock_and_read          : SMB_lock_and_read_response(header);
	#SMB_COM_WRITE_AND_UNLOCK         -> write_and_unlock       : SMB_write_and_unlock_response(header);
	#SMB_COM_READ_RAW                 -> read_raw               : SMB_read_raw_response(header);
	#SMB_COM_READ_MPX                 -> read_mpx               : SMB_read_mpx_response(header);
	#SMB_COM_READ_MPX_SECONDARY       -> read_mpx_secondary     : SMB_read_mpx_secondary_response(header);
	#SMB_COM_WRITE_RAW                -> write_raw              : SMB_write_raw_response(header);
	#SMB_COM_WRITE_MPX                -> write_mpx              : SMB_write_mpx_response(header);
	#SMB_COM_WRITE_MPX_SECONDARY      -> write_mpx_secondary    : SMB_write_mpx_secondary_response(header);
	#SMB_COM_WRITE_COMPLETE           -> write_complete         : SMB_write_complete_response(header);
	#SMB_COM_QUERY_SERVER             -> query_server           : SMB_query_server_response(header);
	#SMB_COM_SET_INFORMATION2         -> set_information2       : SMB_set_information2_response(header);
	#SMB_COM_QUERY_INFORMATION2       -> query_information2     : SMB_query_information2_response(header);
	#SMB_COM_LOCKING_ANDX             -> locking_andx           : SMB_locking_andx_response(header);
	SMB_COM_TRANSACTION              -> transaction            : SMB_transaction_response(header);
	#SMB_COM_IOCTL                    -> ioctl                  : SMB_ioctl_response(header);
	#SMB_COM_IOCTL_SECONDARY          -> ioctl_secondary        : SMB_ioctl_secondary_response(header);
	#SMB_COM_COPY                     -> copy                   : SMB_copy_response(header);
	#SMB_COM_MOVE                     -> move                   : SMB_move_response(header);
	#SMB_COM_ECHO                     -> echo                   : SMB_echo_response(header);
	#SMB_COM_WRITE_AND_CLOSE          -> write_and_close        : SMB_write_and_close_response(header);
	#SMB_COM_OPEN_ANDX                -> open_andx              : SMB_open_andx_response(header);
	SMB_COM_READ_ANDX                -> read_andx              : SMB_read_andx_response(header);
	SMB_COM_WRITE_ANDX               -> write_andx             : SMB_write_andx_response(header);
	#SMB_COM_NEW_FILE_SIZE            -> new_file_size          : SMB_new_file_size_response(header);
	#SMB_COM_CLOSE_AND_TREE_DISC      -> close_and_tree_disc    : SMB_close_and_tree_disc_response(header);
	#SMB_COM_TRANSACTION2             -> transaction2           : SMB_transaction2_response(header);
	#SMB_COM_TRANSACTION2_SECONDARY   -> transaction2_secondary : SMB_transaction2_secondary_response(header);
	#SMB_COM_FIND_CLOSE2              -> find_close2            : SMB_find_close2_response(header);
	#SMB_COM_FIND_NOTIFY_CLOSE        -> find_notify_close      : SMB_find_notify_close_response(header);
	#SMB_COM_TREE_CONNECT             -> tree_connect           : SMB_tree_connect_response(header);
	#SMB_COM_TREE_DISCONNECT          -> tree_disconnect        : SMB_tree_disconnect_response(header);
	SMB_COM_NEGOTIATE                -> negotiate              : SMB_negotiate_response(header);
	#SMB_COM_SESSION_SETUP_ANDX       -> session_setup_andx     : SMB_session_setup_andx_response(header);
	#SMB_COM_LOGOFF_ANDX              -> logoff_andx            : SMB_logoff_andx_response(header);
	SMB_COM_TREE_CONNECT_ANDX        -> tree_connect_andx      : SMB_tree_connect_andx_response(header);
	#SMB_COM_QUERY_INFORMATION_DISK   -> query_information_disk : SMB_query_information_disk_response(header);
	#SMB_COM_SEARCH                   -> search                 : SMB_search_response(header);
	#SMB_COM_FIND                     -> find                   : SMB_find_response(header);
	#SMB_COM_FIND_UNIQUE              -> find_unique            : SMB_find_unique_response(header);
	#SMB_COM_FIND_CLOSE               -> find_close             : SMB_find_close_response(header);
	#SMB_COM_NT_TRANSACT              -> nt_transact            : SMB_nt_transact_response(header);
	#SMB_COM_NT_TRANSACT_SECONDARY    -> nt_transact_secondary  : SMB_nt_transact_secondary_response(header);
	SMB_COM_NT_CREATE_ANDX           -> nt_create_andx         : SMB_nt_create_andx_response(header);
	#SMB_COM_NT_CANCEL                -> nt_cancel              : SMB_nt_cancel_response(header);
	#SMB_COM_NT_RENAME                -> nt_rename              : SMB_nt_rename_response(header);
	#SMB_COM_OPEN_PRINT_FILE          -> open_print_file        : SMB_open_print_file_response(header);
	#SMB_COM_WRITE_PRINT_FILE         -> write_print_file       : SMB_write_print_file_response(header);
	#SMB_COM_CLOSE_PRINT_FILE         -> close_print_file       : SMB_close_print_file_response(header);
	#SMB_COM_GET_PRINT_QUEUE          -> get_print_queue        : SMB_get_print_queue_response(header);
	#SMB_COM_READ_BULK                -> read_bulk              : SMB_read_bulk_response(header);
	#SMB_COM_WRITE_BULK               -> write_bulk             : SMB_write_bulk_response(header);
	#SMB_COM_WRITE_BULK_DATA          -> write_bulk_data        : SMB_write_bulk_data_response(header);
	default                          -> unknown_msg            : empty; # TODO: do something different here!
} &byteorder = littleendian;

type SMB_file_id = uint16;
type SMB_timestamp = uint32;
type SMB_filetime = uint32[2];

type SMB_dos_error = record {
	error_class : uint8;
	reserved    : uint8;
	error       : uint16;
};

type SMB_error(err_status_type: int) = case err_status_type of {
	0 -> dos_error  : SMB_dos_error;
	1 -> status     : uint32;
};

type SMB_Header = record {
	protocol          : bytestring &length = 4;
	command           : uint8;
	status            : SMB_error(err_status_type);
	flags             : uint8;
	flags2            : uint16;
	pid_high          : uint16;
	security_features : uint8[8];
	reserved          : uint16;
	tid               : uint16;
	pid_low           : uint16;
	uid               : uint16;
	mid               : uint16;
} &let {
	err_status_type = (flags2 >> 14) & 1;
	unicode = (flags2 >> 15) & 1;
	pid = pid_high * 0x10000 + pid_low;
};

# TODO: compute this as
# let SMB_Header_length = sizeof(SMB_Header);
let SMB_Header_length = 32;

#type SMB_body = record {
#	word_count	: uint8;
#	parameter_words : uint16[word_count];
#	byte_count	: uint16;
#	# buffer	: uint8[byte_count];
#} &let {
#	body_length = 1 + word_count * 2 + 2 + byte_count;
#} &byteorder = littleendian;

type SMB_ascii_string = uint8[] &until($element == 0);
type SMB_unicode_string(offset: int) = record {
	pad	: padding[offset & 1];
	s	: uint16[] &until($element == 0);
};

type SMB_string(unicode: bool, offset: int) = case unicode of {
	true	-> u: SMB_unicode_string(offset);
	false	-> a: SMB_ascii_string;
};

type SMB_time = record {
	two_seconds : uint16;
	minutes	: uint16;
	hours		: uint16;
} &byteorder = littleendian;

type SMB_date = record {
	day		: uint16;
	month		: uint16;
	year		: uint16;
} &byteorder = littleendian;

type SMB_empty_response(header: SMB_Header) = record {
	word_count   : uint8;
	byte_count   : uint16;
};

type SMB_andx = record {
	command		: uint8;
	reserved	: uint8;
	offset		: uint16;
} &refcount;

type SMB_generic_andx = record {
	word_count	: uint8;
	andx_u		: case word_count of {
		0	-> null : empty;
		default -> andx	: SMB_andx;
	};
	data		: bytestring &restofdata;
} &byteorder = littleendian;

type SMB_dialect = record {
	bufferformat  : uint8; # must be 0x2
	dialectname   : SMB_ascii_string;
};

type SMB_negotiate_request(header: SMB_Header) = record {
	word_count	: uint8;	# must be 0
	byte_count	: uint16;
	dialects	: SMB_dialect[] &length = byte_count;
};

type SMB_negotiate_response(header: SMB_Header) = record {
	word_count      : uint8; # should be 13
	dialect_index   : uint16;
	security_mode   : uint8; # bit 0: 0=share 1=user, bit 1: 1=chalenge/response
	max_mpx_count   : uint16;
	max_number_vcs  : uint16;
	max_buffer_size : uint32;
	max_raw_size    : uint32;
	session_key     : uint32;
	capabilities    : uint32;
	server_time     : SMB_filetime;
	server_tz       : uint16;
	challenge_len   : uint8;
	byte_count      : uint16;
	challenge       : bytestring &length=challenge_len;
	domain_name     : SMB_string(header.unicode, offsetof(domain_name));
};

# pre NT LM 0.12
type SMB_setup_andx_basic(header: SMB_Header) = record {
	word_count	: uint8;
	andx		: SMB_andx;
	max_buffer_size : uint16;
	max_mpx_count	: uint16;
	vc_number	: uint16;
	session_key	: uint32;
	passwd_length	: uint8;
	reserved	: uint32;
	byte_count	: uint8;
	password	: uint8[passwd_length];
	name		: SMB_string(header.unicode, offsetof(name));
	domain		: SMB_string(header.unicode, offsetof(domain));
	native_os	: SMB_string(header.unicode, offsetof(native_os));
	native_lanman	: SMB_string(header.unicode, offsetof(native_lanman));
} &byteorder = littleendian;

type SMB_setup_andx_basic_response(header: SMB_Header) = record {
	word_count	: uint8;
	andx		: SMB_andx;
	action		: uint8;
	byte_count	: uint8;
	native_os	: SMB_string(header.unicode, offsetof(native_os));
	native_lanman	: SMB_string(header.unicode, offsetof(native_lanman));
	primary_domain	: SMB_string(header.unicode, offsetof(primary_domain));
} &byteorder = littleendian;

# NT LM 0.12 && CAP_EXTENDED_SECURITY
type SMB_setup_andx_ext(header: SMB_Header) = record {
	word_count	: uint8;
	andx		: SMB_andx;
	max_buffer_size : uint16;
	max_mpx_count	: uint16;
	vc_number	: uint16;
	session_key	: uint32;
	security_length : uint8;
	reserved	: uint32;
	capabilities	: uint32;
	byte_count	: uint8;
	security_blob	: uint8[security_length];
	native_os	: SMB_string(header.unicode, offsetof(native_os));
	native_lanman	: SMB_string(header.unicode, offsetof(native_lanman));
} &byteorder = littleendian;

type SMB_setup_andx_ext_response(header: SMB_Header) = record {
	word_count	: uint8;
	andx		: SMB_andx;
	action		: uint8;
	security_length : uint8;
	byte_count	: uint8;
	security_blob	: uint8[security_length];
	native_os	: SMB_string(header.unicode, offsetof(native_os));
	native_lanman	: SMB_string(header.unicode, offsetof(native_lanman));
	primary_domain	: SMB_string(header.unicode, offsetof(primary_domain));
};

type SMB_logoff_andx(header: SMB_Header) = record {
	word_count	: uint8;
	andx		: SMB_andx;
	byte_count	: uint16;
};

type SMB_tree_connect_andx_request(header: SMB_Header) = record {
	word_count	: uint8;
	andx		: SMB_andx;
	flags		: uint16;
	password_length	: uint16;
	byte_count	: uint16;
	password	: uint8[password_length];
	path		: SMB_string(header.unicode, offsetof(path));
	service		: SMB_ascii_string;
};

type SMB_tree_connect_andx_response(header: SMB_Header) = record {
	word_count         : uint8;
	andx_command       : uint8;
	andx_reserved      : uint8;
	andx_offset        : uint16;
	optional_support   : uint16;
	pad                : padding[(word_count-3)*2];
	byte_count         : uint16;
	service            : SMB_string(0, offsetof(service));
	pad2               : empty; # TODO: this supposed to be either one or zero bytes if unicode is enabled.
	native_file_system : SMB_string(header.unicode, offsetof(native_file_system));
};

type SMB_close_request(header: SMB_Header) = record {
	word_count           : uint8;
	file_id                  : SMB_file_id;
	last_modified_time   : SMB_timestamp;
	byte_count           : uint16;
} &byteorder = littleendian;

type SMB_tree_disconnect(header: SMB_Header) = record {
	word_count	: uint8;
	byte_count	: uint16;
} &byteorder = littleendian;

type SMB_nt_create_andx_request(header: SMB_Header) = record {
	word_count          : uint8;
	andx                : SMB_andx;
	andx_reserved       : uint8;
	andx_offset         : uint16;
	reserved2           : uint8;
	name_length         : uint16;
	flags               : uint32;
	root_dir_file_id        : SMB_file_id;
	desired_access      : uint32;
	alloc_size          : uint32[2];
	ext_file_attrs      : uint32;
	share_access        : uint32;
	create_disposition  : uint32;
	create_options      : uint32;
	impersonation_level : uint32;
	security_flags      : uint8;
	byte_count          : uint16;
	filename            : SMB_string(header.unicode, offsetof(filename));
} &byteorder = littleendian;

type SMB_nt_create_andx_response(header: SMB_Header) = record {
	word_count          : uint8;
	andx_command        : SMB_andx;
	andx_reserved       : uint8;
	andx_offset         : uint16;
	oplock_level        : uint8;
	file_id             : SMB_file_id;
	create_disposition  : uint32;
	create_time         : SMB_filetime;
	last_access_time    : SMB_filetime;
	last_write_time     : SMB_filetime;
	last_change_time    : SMB_filetime;
	ext_file_attributes : uint32;
	allocation_size     : uint32[2];
	end_of_file         : uint32[2];
	resource_type       : uint16;
	nm_pipe_status      : uint16;
	directory           : uint8;
	byte_count          : uint16;
};


type SMB_read_andx_request(header: SMB_Header) = record {
	word_count     : uint8;
	andx           : SMB_andx;
	file_id        : uint16;
	offset         : uint32;
	max_count      : uint16;
	min_count      : uint16;
	max_count_high : uint16;
	remaining      : uint16;
	offset_high_u  : case word_count of {
		12 -> offset_high : uint32;
		10 -> null        : empty;
	};
	byte_count     : uint16;
};

type SMB_read_andx_response(header: SMB_Header) = record {
	word_count       : uint8;
	andx             : SMB_andx;
	remaining        : uint16;
	data_compact     : uint16;
	reserved         : uint16;
	data_len_low     : uint16;
	data_offset      : uint16;
	data_len_high    : uint16;
	reserved2        : uint16[4];
	byte_count       : uint16;
	pad              : padding[padding_len];
	data             : bytestring &length = data_len;
	# Chris: the length here is causing problems - could we be having
	# issues with the packet format or is the data_len just not
	# right. The problem is that the padding is not always filled right,
	# espeically when its not the first command in the packet.
	#data             : bytestring &restofdata;
} &let {
	data_len    = data_len_high * 0x10000 + data_len_low;
	padding_len = byte_count - data_len;
};

type SMB_write_andx_request(header: SMB_Header) = record {
	word_count    : uint8;
	andx          : SMB_andx;
	file_id       : SMB_file_id;
	offset        : uint32;
	timeout       : uint32;
	write_mode    : uint16;
	remaining     : uint16;
	data_len_high : uint16;
	data_len_low  : uint16;
	data_offset   : uint16;
	offset_high_u : case word_count of {
		14      -> offset_high : uint32;
		12      -> null        : empty;
	};
	
	byte_count    : uint16;
	pad           : uint8;
	data          : bytestring &length=data_len; # TODO: this should be done chunk-wise
} &let {
	data_len = data_len_high * 0x10000 + data_len_low;
};

type SMB_write_andx_response(header: SMB_Header) = record {
	word_count  : uint8;
	andx        : SMB_andx;
	count_low   : uint16; # written bytes
	remaining   : uint16;
	count_high  : uint16;
	reserved    : uint16;
	
	byte_count  : uint16;
} &let {
	written_bytes = count_high * 0x10000 + count_low;
};

type SMB_transaction_data(header: SMB_Header, count: uint16, sub_cmd: uint16,
				trans_type: TransactionType ) = case trans_type of {

	SMB_MAILSLOT_BROWSE -> mailslot : SMB_MailSlot_message(header.unicode, count);
	SMB_MAILSLOT_LANMAN -> lanman : SMB_MailSlot_message(header.unicode, count);
	SMB_RAP -> rap	: SMB_Pipe_message(header.unicode, count, sub_cmd);
	SMB_PIPE -> pipe : SMB_Pipe_message(header.unicode, count, sub_cmd);
	SMB_UNKNOWN -> unknown : bytestring &restofdata;
	default -> data : bytestring &restofdata;

};

type SMB_transaction_request(header: SMB_Header) = record {
	word_count          : uint8;
	total_param_count   : uint16;
	total_data_count    : uint16;
	max_param_count     : uint16;
	max_data_count      : uint16;
	max_setup_count     : uint8;
	reserved1           : uint8;
	flags               : uint16;
	timeout             : uint32;
	reserved2           : uint16;
	param_count         : uint16;
	param_offset        : uint16;
	data_count          : uint16;
	data_offset         : uint16;
	setup_count         : uint8;
	reserved3           : uint8;
	setup               : uint16[setup_count];
	
	byte_count          : uint16;
	name                : SMB_string(header.unicode, offsetof(name));
	pad1	            : padding to param_offset - SMB_Header_length;
	parameters          : bytestring &length = param_count;
	pad2                : padding to data_offset - SMB_Header_length;
	data                : SMB_transaction_data(header, data_count, sub_cmd, determine_transaction_type(setup_count, name));
} &let {
	# does this work?
	sub_cmd : uint16 = setup_count ? setup[0] : 0;
};

type SMB_transaction2_request(header: SMB_Header) = record {
	word_count          : uint8;
	total_param_count   : uint16;
	total_data_count    : uint16;
	max_param_count     : uint16;
	max_data_count      : uint16;
	max_setup_count     : uint8;
	reserved1           : uint8;
	flags               : uint16;
	timeout             : uint32;
	reserved2           : uint16;
	param_count         : uint16;
	param_offset        : uint16;
	data_count          : uint16;
	data_offset         : uint16;
	setup_count         : uint8;
	reserved3           : uint8;
	setup               : uint16[setup_count];

	byte_count          : uint16;
	name                : SMB_string(header.unicode, offsetof(name));
	pad1                : padding to param_offset - SMB_Header_length;
	parameters          : bytestring &length = param_count;
	pad2                : padding to data_offset - SMB_Header_length;
	data                : bytestring &length = data_count; # TODO: make SMB_transaction2_data structure -- SMB_transaction_data(header, data_count, 0, SMB_UNKNOWN);
};

type SMB_transaction2_response(header: SMB_Header) = record {
	word_count          : uint8;
	total_param_count   : uint16;
	total_data_count    : uint16;
	reserved1           : uint16;
	param_count         : uint16;
	param_offset        : uint16;
	param_displacement  : uint16;
	data_count          : uint16;
	data_offset         : uint16;
	data_displacement   : uint16;
	setup_count         : uint8;
	reserved2           : uint8;
	setup               : uint16[setup_count];

	byte_count          : uint16;
	pad1                : padding to param_offset - SMB_Header_length;
	parameters          : bytestring &length = param_count;
	pad2                : padding to data_offset - SMB_Header_length;
	data                : bytestring &length = data_count; # TODO: make SMB_transaction2_data structure -- SMB_transaction_data(header, data_count, 0, SMB_UNKNOWN);
};


type SMB_transaction_secondary_request(header: SMB_Header) = record {
	word_count          : uint8;
	total_param_count   : uint16;
	total_data_count    : uint16;
	param_count         : uint16;
	param_offset        : uint16;
	param_displacement  : uint16;
	data_count          : uint16;
	data_offset         : uint16;
	data_displacement   : uint16;
	
	byte_count          : uint16;
	pad1                : padding to param_offset - SMB_Header_length;
	parameters          : bytestring &length = param_count;
	pad2                : padding to data_offset - SMB_Header_length;
	data                : SMB_transaction_data(header, data_count, 0, SMB_UNKNOWN);
};


type SMB_transaction_response(header: SMB_Header) = record {
	word_count          : uint8;
	total_param_count   : uint16;
	total_data_count    : uint16;
	reserved            : uint16;
	param_count         : uint16;
	param_offset        : uint16;
	param_displacement  : uint16;
	data_count          : uint16;
	data_offset         : uint16;
	data_displacement   : uint16;
	setup_count         : uint8;
	reserved2           : uint8;
	setup               : uint16[setup_count];
	
	byte_count          : uint16;
	pad0                : padding to param_offset - SMB_Header_length;
	parameters          : bytestring &length = param_count;
	pad1                : padding to data_offset - SMB_Header_length;
	data                : SMB_transaction_data(header, data_count, 0, SMB_UNKNOWN);
};

type SMB_create_directory_request(header: SMB_Header) = record {
	word_count      : uint8;
	byte_count      : uint16;
	buffer_format   : uint8;
	directory_name  : SMB_string(header.unicode, offsetof(directory_name));
};

type SMB_create_directory_response(header: SMB_Header) = record {
	word_count      : uint8;
	byte_count      : uint16;
};

type SMB_get_dfs_referral(header: SMB_Header) = record {
	max_referral_level	: uint16;
	file_name		: SMB_string(header.unicode, offsetof(file_name));
};

type SMB_nt_transact(header: SMB_Header) = record {
	word_count          : uint8;
} &byteorder = littleendian;