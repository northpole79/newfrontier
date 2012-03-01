# CIFS/SMB

# TODO:
# - Built support for unicode strings
# - Unicode as an implicit attribute (as byteorder)
# - &truncation_ok attribute for the last field of a record to deal with partial data

enum SMBVersion {
	SMB1 = 0xff534d42, # \xffSMB
	SMB2 = 0xfe534d42, # \xfeSMB
};

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

enum Trans2_subcommands {
	# Commented out items are deprecated or removed from the spec.
	TRANS2_OPEN2 = 0x0000,
	TRANS2_FIND_FIRST2 = 0x0001,
	TRANS2_FIND_NEXT2 = 0x0002,
	TRANS2_QUERY_FS_INFORMATION = 0x0003,
	TRANS2_SET_FS_INFORMATION = 0x0004,
	TRANS2_QUERY_PATH_INFORMATION = 0x0005,
	TRANS2_SET_PATH_INFORMATION = 0x0006,
	TRANS2_QUERY_FILE_INFORMATION = 0x0007,
	TRANS2_SET_FILE_INFORMATION = 0x0008,
	#TRANS2_FSCTL = 0x0009,
	#TRANS2_IOCTL2 = 0x000a,
	#TRANS2_FIND_NOTIFY_FIRST = 0x000b,
	#TRANS2_FIND_NOTIFY_NEXT = 0x000c,
	TRANS2_CREATE_DIRECTORY = 0x000d,
	#TRANS2_SESSION_SETUP = 0x000e,
	TRANS2_GET_DFS_REFERRAL = 0x0010,
	#TRANS2_REPORT_DFS_INCONSISTENCY 0x0011,
};

enum Trans_subcommands {
	NT_TRANSACT_QUERY_QUOTA = 0x0007,
	NT_TRANSACT_SET_QUOTA = 0x0008,
	NT_TRANSACT_CREATE2 = 0x0009,
};

enum SMB_Status {
	STATUS_SUCCESS = 0x00000000,
	STATUS_INVALID_SMB = 0x00010002,
	STATUS_SMB_BAD_TID = 0x00050002,
	STATUS_SMB_BAD_COMMAND = 0x00160002,
	STATUS_SMB_BAD_UID = 0x005B0002,
	STATUS_SMB_USE_STANDARD = 0x00FB0002,
	STATUS_BUFFER_OVERFLOW = 0x80000005,
	STATUS_NO_MORE_FILES = 0x80000006,
	STATUS_STOPPED_ON_SYMLINK = 0x8000002D,
	STATUS_NOT_IMPLEMENTED = 0xC0000002,
	STATUS_INVALID_PARAMETER = 0xC000000D,
	STATUS_NO_SUCH_DEVICE = 0xC000000E,
	STATUS_INVALID_DEVICE_REQUEST = 0xC0000010,
	STATUS_MORE_PROCESSING_REQUIRED = 0xC0000016,
	STATUS_ACCESS_DENIED = 0xC0000022,
	STATUS_BUFFER_TOO_SMALL = 0xC0000023,
	STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034,
	STATUS_OBJECT_NAME_COLLISION = 0xC0000035,
	STATUS_OBJECT_PATH_NOT_FOUND = 0xC000003A,
	STATUS_BAD_IMPERSONATION_LEVEL = 0xC00000A5,
	STATUS_IO_TIMEOUT = 0xC00000B5,
	STATUS_FILE_IS_A_DIRECTORY = 0xC00000BA,
	STATUS_NOT_SUPPORTED = 0xC00000BB,
	STATUS_NETWORK_NAME_DELETED = 0xC00000C9,
	STATUS_USER_SESSION_DELETED = 0xC0000203,
	STATUS_NETWORK_SESSION_EXPIRED = 0xC000035C,
	STATUS_SMB_TOO_MANY_UIDS = 0xC000205A,
};

function filetime2brotime(ts: int64): Val
	%{
	double secs = (ts / 10000000);
	// TODO: subsecond accuracy is broken right now.
	//double nanosecs = (ts - secs) * 100.0;
	//printf("nanosecs: %f\n", nanosecs);
	//if ( nanosecs > 0 )
	//	secs += (1000000000/nanosecs);
	// Bro can't support times back to the 1600's 
	// so we subtract a lot of seconds.
	Val* bro_ts = new Val(secs - 11644473600.0, TYPE_TIME);
	
	return bro_ts;
	%}


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

	// If the last character is a null, cut it with the length.
	if ( length > 0 && buf[length-1] == 0 )
		length--;
	
	return bytestring((uint8*) buf, length);
	%}
	
function smb_string2stringval(s: SMB_string) : StringVal
	%{
	const_bytestring str_val = extract_string(s);
	return new StringVal(str_val.length(), (const char*) str_val.begin());
	%}

function determine_transaction_type(setup_count: int, name: SMB_string): TransactionType
	%{
	// This logic needs to be verified! the relationship between
	// setup_count and type is very unclear.
	if ( name == NULL )
		{
		return SMB_UNKNOWN;
		}
	if ( bytestring_caseprefix( extract_string(name),
			"\\PIPE\\LANMAN" ) )
		{
		return SMB_RAP;
		}
	
	if ( bytestring_caseprefix( extract_string(name), "\\MAILSLOT\\LANMAN" ) )
		{
		return SMB_MAILSLOT_LANMAN;
		//return SMB_MAILSLOT_BROWSE;
		}
	
	if ( bytestring_caseprefix( extract_string(name), "\\MAILSLOT\\NET\\NETLOGON" ) )
		{
		/* Don't really know what to do here, its got a Mailslot
		 * type but its a deprecated packet format that handles
		 * old windows logon
		 */
		return SMB_UNKNOWN;
		}
	
	if ( setup_count == 2 ||
	     bytestring_caseprefix( extract_string(name), "\\PIPE\\" ) )
		{
		return SMB_PIPE;
		}
	
	if ( setup_count == 3 ||
	     bytestring_caseprefix( extract_string(name), "\\MAILSLOT\\" ) )
		{
		return SMB_MAILSLOT_BROWSE;
		}
	
	return SMB_UNKNOWN;
	%}
	
type SMB_TCP(is_orig: bool) = record {
	# These are technically NetBIOS fields but it's considered 
	# to be SMB directly over TCP.  The fields are essentially
	# the NBSS protocol but it's only used for framing here.
	message_type : uint8;
	len24        : uint24;
	body         : case message_type of {
		# SMB/SMB2 packets are required to use NBSS session messages.
		0       -> nbss : SMB_Protocol_Identifier(is_orig);
		default -> skip : empty;
	};
} &let {
	len : uint32 = to_int(len24);
} &byteorder = littleendian &length=len+4;

type SMB_Protocol_Identifier(is_orig: bool) = record {
	# Sort of cheating by reading this in as an integer instead of a string.
	protocol          : uint32 &byteorder=bigendian;
	smb_1_or_2        : case protocol of {
		SMB1    -> smb1    : SMB_PDU(is_orig);
		SMB2    -> smb2    : SMB2_PDU(is_orig);
		default -> unknown : empty;
	};
};

type SMB_PDU(is_orig: bool) = record {
	header     : SMB_Header(is_orig);
	message    : case header.status.error of {
		STATUS_MORE_PROCESSING_REQUIRED  -> more_proc : SMB_Message(header, header.command, is_orig);
		0                                -> msg       : SMB_Message(header, header.command, is_orig);
		default                          -> no_msg    : uint8[3];
	};
};

type SMB_Message(header: SMB_Header, command: uint8, is_orig: bool) = case is_orig of {
	true    ->  request   : SMB_Message_Request(header, command, is_orig);
	false   ->  response  : SMB_Message_Response(header, command, is_orig);
};

type SMB_andx_command(header: SMB_Header, is_orig: bool, command: uint8) = case command of {
	0xff    -> no_futher_commands : empty;
	default -> message            : SMB_Message(header, command, is_orig);
};

type SMB_Data(pad_bytes: uint8, len: uint16) = record {
	byte_count : uint16;
	pad1       : padding[pad_bytes];
	data       : bytestring &length=len;
};

type SMB_Message_Request(header: SMB_Header, command: uint8, is_orig: bool) = case command of {
	# SMB1 Command Extensions
	#SMB_COM_OPEN_ANDX                -> open_andx              : SMB_open_andx_request(header);
	SMB_COM_READ_ANDX                -> read_andx              : SMB_read_andx_request(header);
	SMB_COM_WRITE_ANDX               -> write_andx             : SMB_write_andx_request(header);
	#SMB_COM_TRANSACTION2             -> transaction2           : SMB_transaction2_request(header);
	SMB_COM_NEGOTIATE                -> negotiate              : SMB_negotiate_request(header);
	SMB_COM_SESSION_SETUP_ANDX       -> session_setup_andx     : SMB_session_setup_andx_request(header);
	SMB_COM_TREE_CONNECT_ANDX        -> tree_connect_andx      : SMB_tree_connect_andx_request(header);
	#SMB_COM_NT_TRANSACT              -> nt_transact            : SMB_nt_transact_request(header);
	SMB_COM_NT_CREATE_ANDX           -> nt_create_andx         : SMB_nt_create_andx_request(header);

#	SMB_COM_CREATE_DIRECTORY         -> create_directory       : SMB_create_directory_request(header);
#	#SMB_COM_DELETE_DIRECTORY         -> delete_directory       : SMB_delete_directory_request(header);
#	#SMB_COM_OPEN                     -> open                   : SMB_open_request(header);
#	#SMB_COM_CREATE                   -> create                 : SMB_create_request(header);
	SMB_COM_CLOSE                    -> close                  : SMB_close_request(header);
#	#SMB_COM_FLUSH                    -> flush                  : SMB_flush_request(header);
#	#SMB_COM_DELETE                   -> delete                 : SMB_delete_request(header);
#	#SMB_COM_RENAME                   -> rename                 : SMB_rename_request(header);
	SMB_COM_QUERY_INFORMATION        -> query_information      : SMB_query_information_request(header);
#	#SMB_COM_SET_INFORMATION          -> set_information        : SMB_set_information_request(header);
#	#SMB_COM_READ                     -> read                   : SMB_read_request(header);
#	#SMB_COM_WRITE                    -> write                  : SMB_write_request(header);
#	#SMB_COM_LOCK_BYTE_RANGE          -> lock_byte_range        : SMB_lock_byte_range_request(header);
#	#SMB_COM_UNLOCK_BYTE_RANGE        -> unlock_byte_range      : SMB_unlock_byte_range_request(header);
#	#SMB_COM_CREATE_TEMPORARY         -> create_temporary       : SMB_create_temporary_request(header);
#	#SMB_COM_CREATE_NEW               -> create_new             : SMB_create_new_request(header);
#	#SMB_COM_CHECK_DIRECTORY          -> check_directory        : SMB_check_directory_request(header);
#	#SMB_COM_PROCESS_EXIT             -> process_exit           : SMB_process_exit_request(header);
#	#SMB_COM_SEEK                     -> seek                   : SMB_seek_request(header);
#	#SMB_COM_LOCK_AND_READ            -> lock_and_read          : SMB_lock_and_read_request(header);
#	#SMB_COM_WRITE_AND_UNLOCK         -> write_and_unlock       : SMB_write_and_unlock_request(header);
#	#SMB_COM_READ_RAW                 -> read_raw               : SMB_read_raw_request(header);
#	#SMB_COM_READ_MPX                 -> read_mpx               : SMB_read_mpx_request(header);
#	#SMB_COM_READ_MPX_SECONDARY       -> read_mpx_secondary     : SMB_read_mpx_secondary_request(header);
#	#SMB_COM_WRITE_RAW                -> write_raw              : SMB_write_raw_request(header);
#	#SMB_COM_WRITE_MPX                -> write_mpx              : SMB_write_mpx_request(header);
#	#SMB_COM_WRITE_MPX_SECONDARY      -> write_mpx_secondary    : SMB_write_mpx_secondary_request(header);
#	#SMB_COM_WRITE_COMPLETE           -> write_complete         : SMB_write_complete_request(header);
#	#SMB_COM_QUERY_SERVER             -> query_server           : SMB_query_server_request(header);
#	#SMB_COM_SET_INFORMATION2         -> set_information2       : SMB_set_information2_request(header);
#	#SMB_COM_QUERY_INFORMATION2       -> query_information2     : SMB_query_information2_request(header);
#	#SMB_COM_LOCKING_ANDX             -> locking_andx           : SMB_locking_andx_request(header);
#	SMB_COM_TRANSACTION              -> transaction            : SMB_transaction_request(header);
#	SMB_COM_TRANSACTION_SECONDARY    -> transaction_secondary  : SMB_transaction_secondary_request(header);
#	#SMB_COM_IOCTL                    -> ioctl                  : SMB_ioctl_request(header);
#	#SMB_COM_IOCTL_SECONDARY          -> ioctl_secondary        : SMB_ioctl_secondary_request(header);
#	#SMB_COM_COPY                     -> copy                   : SMB_copy_request(header);
#	#SMB_COM_MOVE                     -> move                   : SMB_move_request(header);
#	#SMB_COM_ECHO                     -> echo                   : SMB_echo_request(header);
#	#SMB_COM_WRITE_AND_CLOSE          -> write_and_close        : SMB_write_and_close_request(header);
#	#SMB_COM_NEW_FILE_SIZE            -> new_file_size          : SMB_new_file_size_request(header);
#	#SMB_COM_CLOSE_AND_TREE_DISC      -> close_and_tree_disc    : SMB_close_and_tree_disc_request(header);
#	#SMB_COM_TRANSACTION2_SECONDARY   -> transaction2_secondary : SMB_transaction2_secondary_request(header);
#	#SMB_COM_FIND_CLOSE2              -> find_close2            : SMB_find_close2_request(header);
#	#SMB_COM_FIND_NOTIFY_CLOSE        -> find_notify_close      : SMB_find_notify_close_request(header);
#	#SMB_COM_TREE_CONNECT             -> tree_connect           : SMB_tree_connect_request(header);
	SMB_COM_TREE_DISCONNECT          -> tree_disconnect        : SMB_tree_disconnect(header, is_orig);
	SMB_COM_LOGOFF_ANDX              -> logoff_andx            : SMB_logoff_andx(header, is_orig);
#	#SMB_COM_QUERY_INFORMATION_DISK   -> query_information_disk : SMB_query_information_disk_request(header);
#	#SMB_COM_SEARCH                   -> search                 : SMB_search_request(header);
#	#SMB_COM_FIND                     -> find                   : SMB_find_request(header);
#	#SMB_COM_FIND_UNIQUE              -> find_unique            : SMB_find_unique_request(header);
#	#SMB_COM_FIND_CLOSE               -> find_close             : SMB_find_close_request(header);
#	#SMB_COM_NT_TRANSACT_SECONDARY    -> nt_transact_secondary  : SMB_nt_transact_secondary_request(header);
#	#SMB_COM_NT_CANCEL                -> nt_cancel              : SMB_nt_cancel_request(header);
#	#SMB_COM_NT_RENAME                -> nt_rename              : SMB_nt_rename_request(header);
#	#SMB_COM_OPEN_PRINT_FILE          -> open_print_file        : SMB_open_print_file_request(header);
#	#SMB_COM_WRITE_PRINT_FILE         -> write_print_file       : SMB_write_print_file_request(header);
#	#SMB_COM_CLOSE_PRINT_FILE         -> close_print_file       : SMB_close_print_file_request(header);
#	#SMB_COM_GET_PRINT_QUEUE          -> get_print_queue        : SMB_get_print_queue_request(header);
#	#SMB_COM_READ_BULK                -> read_bulk              : SMB_read_bulk_request(header);
#	#SMB_COM_WRITE_BULK               -> write_bulk             : SMB_write_bulk_request(header);
#	#SMB_COM_WRITE_BULK_DATA          -> write_bulk_data        : SMB_write_bulk_data_request(header);
	default                          -> unknown_msg            : bytestring &restofdata; # TODO: do something different here!
} &byteorder = littleendian;

type SMB_Message_Response(header: SMB_Header, command: uint8, is_orig: bool) = case command of {
	# SMB1 Command Extensions
	#SMB_COM_OPEN_ANDX                -> open_andx              : SMB_open_andx_response(header);
	SMB_COM_READ_ANDX                -> read_andx              : SMB_read_andx_response(header);
	SMB_COM_WRITE_ANDX               -> write_andx             : SMB_write_andx_response(header);
	#SMB_COM_TRANSACTION2             -> transaction2           : SMB_transaction2_response(header);
	SMB_COM_NEGOTIATE                -> negotiate              : SMB_negotiate_response(header);
	SMB_COM_SESSION_SETUP_ANDX       -> session_setup_andx     : SMB_session_setup_andx_response(header);
	SMB_COM_TREE_CONNECT_ANDX        -> tree_connect_andx      : SMB_tree_connect_andx_response(header);
	#SMB_COM_NT_TRANSACT              -> nt_transact            : SMB_nt_transact_response(header);
	SMB_COM_NT_CREATE_ANDX           -> nt_create_andx         : SMB_nt_create_andx_response(header);

#	SMB_COM_CREATE_DIRECTORY         -> create_directory       : SMB_create_directory_response(header);
#	#SMB_COM_DELETE_DIRECTORY         -> delete_directory       : SMB_delete_directory_response(header);
#	#SMB_COM_OPEN                     -> open                   : SMB_open_response(header);
#	#SMB_COM_CREATE                   -> create                 : SMB_create_response(header);
	SMB_COM_CLOSE                    -> close                  : SMB_empty_response(header);
#	#SMB_COM_FLUSH                    -> flush                  : SMB_flush_response(header);
#	#SMB_COM_DELETE                   -> delete                 : SMB_delete_response(header);
#	#SMB_COM_RENAME                   -> rename                 : SMB_rename_response(header);
	SMB_COM_QUERY_INFORMATION        -> query_information      : SMB_query_information_response(header);
#	#SMB_COM_SET_INFORMATION          -> set_information        : SMB_set_information_response(header);
#	#SMB_COM_READ                     -> read                   : SMB_read_response(header);
#	#SMB_COM_WRITE                    -> write                  : SMB_write_response(header);
#	#SMB_COM_LOCK_BYTE_RANGE          -> lock_byte_range        : SMB_lock_byte_range_response(header);
#	#SMB_COM_UNLOCK_BYTE_RANGE        -> unlock_byte_range      : SMB_unlock_byte_range_response(header);
#	#SMB_COM_CREATE_TEMPORARY         -> create_temporary       : SMB_create_temporary_response(header);
#	#SMB_COM_CREATE_NEW               -> create_new             : SMB_create_new_response(header);
#	#SMB_COM_CHECK_DIRECTORY          -> check_directory        : SMB_check_directory_response(header);
#	#SMB_COM_PROCESS_EXIT             -> process_exit           : SMB_process_exit_response(header);
#	#SMB_COM_SEEK                     -> seek                   : SMB_seek_response(header);
#	#SMB_COM_LOCK_AND_READ            -> lock_and_read          : SMB_lock_and_read_response(header);
#	#SMB_COM_WRITE_AND_UNLOCK         -> write_and_unlock       : SMB_write_and_unlock_response(header);
#	#SMB_COM_READ_RAW                 -> read_raw               : SMB_read_raw_response(header);
#	#SMB_COM_READ_MPX                 -> read_mpx               : SMB_read_mpx_response(header);
#	#SMB_COM_READ_MPX_SECONDARY       -> read_mpx_secondary     : SMB_read_mpx_secondary_response(header);
#	#SMB_COM_WRITE_RAW                -> write_raw              : SMB_write_raw_response(header);
#	#SMB_COM_WRITE_MPX                -> write_mpx              : SMB_write_mpx_response(header);
#	#SMB_COM_WRITE_MPX_SECONDARY      -> write_mpx_secondary    : SMB_write_mpx_secondary_response(header);
#	#SMB_COM_WRITE_COMPLETE           -> write_complete         : SMB_write_complete_response(header);
#	#SMB_COM_QUERY_SERVER             -> query_server           : SMB_query_server_response(header);
#	#SMB_COM_SET_INFORMATION2         -> set_information2       : SMB_set_information2_response(header);
#	#SMB_COM_QUERY_INFORMATION2       -> query_information2     : SMB_query_information2_response(header);
#	#SMB_COM_LOCKING_ANDX             -> locking_andx           : SMB_locking_andx_response(header);
#	SMB_COM_TRANSACTION              -> transaction            : SMB_transaction_response(header);
#	#SMB_COM_IOCTL                    -> ioctl                  : SMB_ioctl_response(header);
#	#SMB_COM_IOCTL_SECONDARY          -> ioctl_secondary        : SMB_ioctl_secondary_response(header);
#	#SMB_COM_COPY                     -> copy                   : SMB_copy_response(header);
#	#SMB_COM_MOVE                     -> move                   : SMB_move_response(header);
#	#SMB_COM_ECHO                     -> echo                   : SMB_echo_response(header);
#	#SMB_COM_WRITE_AND_CLOSE          -> write_and_close        : SMB_write_and_close_response(header);
#	#SMB_COM_NEW_FILE_SIZE            -> new_file_size          : SMB_new_file_size_response(header);
#	#SMB_COM_CLOSE_AND_TREE_DISC      -> close_and_tree_disc    : SMB_close_and_tree_disc_response(header);
#	#SMB_COM_TRANSACTION2_SECONDARY   -> transaction2_secondary : SMB_transaction2_secondary_response(header);
#	#SMB_COM_FIND_CLOSE2              -> find_close2            : SMB_find_close2_response(header);
#	#SMB_COM_FIND_NOTIFY_CLOSE        -> find_notify_close      : SMB_find_notify_close_response(header);
#	#SMB_COM_TREE_CONNECT             -> tree_connect           : SMB_tree_connect_response(header);
	SMB_COM_TREE_DISCONNECT          -> tree_disconnect        : SMB_tree_disconnect(header, is_orig);
	SMB_COM_LOGOFF_ANDX              -> logoff_andx            : SMB_logoff_andx(header, is_orig);
#	#SMB_COM_QUERY_INFORMATION_DISK   -> query_information_disk : SMB_query_information_disk_response(header);
#	#SMB_COM_SEARCH                   -> search                 : SMB_search_response(header);
#	#SMB_COM_FIND                     -> find                   : SMB_find_response(header);
#	#SMB_COM_FIND_UNIQUE              -> find_unique            : SMB_find_unique_response(header);
#	#SMB_COM_FIND_CLOSE               -> find_close             : SMB_find_close_response(header);
#	#SMB_COM_NT_TRANSACT_SECONDARY    -> nt_transact_secondary  : SMB_nt_transact_secondary_response(header);
#	#SMB_COM_NT_CANCEL                -> nt_cancel              : SMB_nt_cancel_response(header);
#	#SMB_COM_NT_RENAME                -> nt_rename              : SMB_nt_rename_response(header);
#	#SMB_COM_OPEN_PRINT_FILE          -> open_print_file        : SMB_open_print_file_response(header);
#	#SMB_COM_WRITE_PRINT_FILE         -> write_print_file       : SMB_write_print_file_response(header);
#	#SMB_COM_CLOSE_PRINT_FILE         -> close_print_file       : SMB_close_print_file_response(header);
#	#SMB_COM_GET_PRINT_QUEUE          -> get_print_queue        : SMB_get_print_queue_response(header);
#	#SMB_COM_READ_BULK                -> read_bulk              : SMB_read_bulk_response(header);
#	#SMB_COM_WRITE_BULK               -> write_bulk             : SMB_write_bulk_response(header);
#	#SMB_COM_WRITE_BULK_DATA          -> write_bulk_data        : SMB_write_bulk_data_response(header);
	default                          -> unknown_msg            : bytestring &restofdata;
} &byteorder = littleendian;

type SMB_file_id = uint16;
type SMB_timestamp = uint32;

type SMB_dos_error = record {
	error_class : uint8;
	reserved    : uint8;
	error       : uint16;
};

type SMB_error(err_status_type: int) = case err_status_type of {
	0       -> dos_error  : SMB_dos_error;
	default -> error      : uint32;
};

type SMB_Header(is_orig: bool) = record {
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
	unicode         = (flags2 >> 15) & 1;
	pid             = (pid_high * 0x10000) + pid_low;
} &byteorder=littleendian;

# TODO: compute this as
# let SMB_Header_length = sizeof(SMB_Header);
let SMB_Header_length = 32;

type SMB_ascii_string = uint8[] &until($element == 0x00);
type SMB_unicode_string(offset: int) = record {
	pad : padding[offset & 1];
	s   : uint16[] &until($element == 0x0000);
} &byteorder=littleendian;

type SMB_string(unicode: bool, offset: int) = case unicode of {
	true  -> u: SMB_unicode_string(offset);
	false -> a: SMB_ascii_string;
};

type SMB_time = record {
	two_seconds : uint16;
	minutes     : uint16;
	hours       : uint16;
} &byteorder = littleendian;

type SMB_date = record {
	day   : uint16;
	month : uint16;
	year  : uint16;
} &byteorder = littleendian;

type SMB_empty_response(header: SMB_Header) = record {
	word_count   : uint8;
	byte_count   : uint16;
};

type SMB_andx = record {
	command  : uint8;
	reserved : uint8;
	offset   : uint16;
} &byteorder = littleendian;

type SMB_dialect = record {
	buffer_format  : uint8; # must be 0x2 for dialect
	name           : SMB_string(0,0);
};

type SMB_negotiate_request(header: SMB_Header) = record {
	word_count  : uint8;	# must be 0
	byte_count  : uint16;
	dialects    : SMB_dialect[] &length=byte_count;
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
	server_time     : uint64;
	server_tz       : uint16;
	challenge_len   : uint8;
	byte_count      : uint16;
	challenge       : bytestring &length=challenge_len;
	domain_name     : SMB_string(header.unicode, offsetof(domain_name));
};


# These next two types aren't used right now and are quite old.
# pre NT LM 0.12
#type SMB_session_setup_andx_basic_request(header: SMB_Header) = record {
#	word_count      : uint8;
#	andx            : SMB_andx;
#	max_buffer_size : uint16;
#	max_mpx_count   : uint16;
#	vc_number       : uint16;
#	session_key     : uint32;
#	passwd_length   : uint8;
#	reserved        : uint32;
#	byte_count      : uint8;
#	password        : uint8[passwd_length];
#	domain          : SMB_string(header.unicode, offsetof(domain));
#	native_os       : SMB_string(header.unicode, offsetof(native_os));
#	native_lanman   : SMB_string(header.unicode, offsetof(native_lanman));
#} &byteorder = littleendian;
#
#type SMB_session_setup_andx_basic_response(header: SMB_Header) = record {
#	word_count      : uint8;
#	andx            : SMB_andx;
#	action          : uint8;
#	byte_count      : uint8;
#	native_os       : SMB_string(header.unicode, offsetof(native_os));
#	native_lanman   : SMB_string(header.unicode, offsetof(native_lanman));
#	primary_domain  : SMB_string(header.unicode, offsetof(primary_domain));
#} &byteorder = littleendian;

# NT LM 0.12 && CAP_EXTENDED_SECURITY
type SMB_session_setup_andx_request(header: SMB_Header) = record {
	word_count       : uint8;
	andx             : SMB_andx;
	max_buffer_size  : uint16;
	max_mpx_count    : uint16;
	vc_number        : uint16;
	session_key      : uint32;
	security_length  : uint16;
	reserved         : uint32;
	capabilities     : uint32;
	
	byte_count       : uint16;
	security_blob    : uint8[security_length];
	native_os        : SMB_string(header.unicode, offsetof(native_os));
	native_lanman    : SMB_string(header.unicode, offsetof(native_lanman));
	
	andx_command     : SMB_andx_command(header, 1, andx.command);
} &byteorder = littleendian;

type SMB_session_setup_andx_response(header: SMB_Header) = record {
	word_count       : uint8;
	andx             : SMB_andx;
	action           : uint16;
	security_length  : uint16;
	
	byte_count       : uint16;
	security_blob    : uint8[security_length];
	native_os        : SMB_string(header.unicode, offsetof(native_os));
	native_lanman    : SMB_string(header.unicode, offsetof(native_lanman));
	primary_domain   : SMB_string(header.unicode, offsetof(primary_domain));
	
	andx_command     : SMB_andx_command(header, 1, andx.command);
};

type SMB_logoff_andx(header: SMB_Header, is_orig: bool) = record {
	word_count  : uint8;
	andx        : SMB_andx;
	byte_count  : uint16;
};

type SMB_tree_connect_andx_request(header: SMB_Header) = record {
	word_count      : uint8;
	andx	        : SMB_andx;
	flags	        : uint16;
	password_length : uint16;
	byte_count      : uint16;
	password        : uint8[password_length];
	path            : SMB_string(header.unicode, offsetof(path));
	service         : SMB_string(0, offsetof(service));
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
	native_file_system : SMB_string(header.unicode, offsetof(native_file_system));
};

type SMB_close_request(header: SMB_Header) = record {
	word_count           : uint8;
	file_id              : SMB_file_id;
	last_modified_time   : SMB_timestamp;
	
	byte_count           : uint16;
} &byteorder = littleendian;

type SMB_tree_disconnect(header: SMB_Header, is_orig: bool) = record {
	word_count : uint8;
	byte_count : uint16;
} &byteorder = littleendian;

type SMB_nt_create_andx_request(header: SMB_Header) = record {
	word_count          : uint8;
	andx                : SMB_andx;
	reserved            : uint8;
	
	name_length         : uint16;
	flags               : uint32;
	root_dir_file_id    : uint32;
	desired_access      : uint32;
	alloc_size          : uint64;
	ext_file_attrs      : uint32;
	share_access        : uint32;
	create_disposition  : uint32;
	create_options      : uint32;
	impersonation_level : uint32;
	security_flags      : uint8;
	
	byte_count          : uint16;
	filename            : SMB_string(header.unicode, offsetof(filename));
	
	andx_command        : SMB_andx_command(header, 1, andx.command);
} &byteorder = littleendian;

type SMB_nt_create_andx_response(header: SMB_Header) = record {
	word_count         : uint8;
	andx               : SMB_andx;
	oplock_level       : uint8;
	file_id            : SMB_file_id;
	create_disposition : uint32;
	create_time        : int64;
	last_access_time   : int64;
	last_write_time    : int64;
	last_change_time   : int64;
	ext_file_attrs     : uint32;
	allocation_size    : uint64;
	end_of_file        : uint64;
	resource_type      : uint16;
	nm_pipe_status     : uint16;
	directory          : uint8;
	
	byte_count         : uint16;
} &byteorder=littleendian;


type SMB_read_andx_request(header: SMB_Header) = record {
	word_count     : uint8;
	andx           : SMB_andx;
	file_id        : uint16;
	offset_low     : uint32;
	max_count_low  : uint16;
	min_count      : uint16;
	max_count_high : uint32;
	remaining      : uint16;
	offset_high_u  : case word_count of {
		0x0C    -> offset_high_tmp : uint32;
		default -> null            : empty;
	};
	byte_count     : uint16;
} &let {
	offset_high : uint32 = (word_count == 0x0C) ? offset_high_tmp : 0;
	offset      : uint32 = (offset_high * 0x10000) + offset_low;
	max_count   : uint32 = (max_count_high * 0x10000) + max_count_low;
} &byteorder=littleendian;

type SMB_read_andx_response(header: SMB_Header) = record {
	word_count        : uint8;
	andx              : SMB_andx;
	available         : uint16;
	data_compact_mode : uint16;
	reserved1         : uint16;
	data_len_low      : uint16;
	data_offset       : uint16;
	data_len_high     : uint16;
	reserved2         : uint64;
	
	byte_count        : uint16;
	pad               : padding to data_offset - SMB_Header_length;
	data              : bytestring &length=data_len;
} &let {
	padding_len : uint8  = (header.unicode == 1) ? 1 : 0;
	data_len    : uint32 = (data_len_high << 16) + data_len_low;
} &byteorder=littleendian;

type SMB_write_andx_request(header: SMB_Header) = record {
	word_count    : uint8;
	andx          : SMB_andx;
	file_id       : SMB_file_id;
	offset_low    : uint32;
	timeout       : uint32;
	write_mode    : uint16;
	remaining     : uint16;
	data_len_high : uint16;
	data_len_low  : uint16;
	data_offset   : uint16;
	offset_high_u : case word_count of {
		0x0E      -> offset_high_tmp : uint32;
		default   -> null            : empty;
	};
	
	byte_count    : uint16;
	pad           : padding to data_offset - SMB_Header_length;
	data          : bytestring &length=data_len;
} &let {
	data_len    : uint32 = (data_len_high << 16) + data_len_low;
	offset_high : uint32 = (word_count == 0x0E) ? offset_high_tmp : 0;
	offset      : uint32 = (offset_high * 0x10000) + offset_low;
};

type SMB_write_andx_response(header: SMB_Header) = record {
	word_count   : uint8;
	andx         : SMB_andx;
	written_low  : uint16;
	remaining    : uint16;
	written_high : uint16;
	reserved     : uint16;
	
	byte_count  : uint16;
} &let {
	written_bytes : uint32 = (written_high * 0x10000) + written_low;
};

type SMB_query_information_request(header: SMB_Header) = record {
	word_count    : uint8;
	
	byte_count    : uint16;
	buffer_format : uint8;
	filename      : SMB_string(header.unicode, offsetof(filename));
};

type SMB_query_information_response(header: SMB_Header) = record {
	word_count      : uint8;
	file_attribs    : uint16;
	last_write_time : SMB_time;
	file_size       : uint32;
	reserved        : uint16[5];
	byte_count      : uint16 &check($element == 0);
};


type SMB_transaction_data(header: SMB_Header, count: uint16, sub_cmd: uint16,
                          trans_type: TransactionType ) = case trans_type of {
	SMB_MAILSLOT_BROWSE -> mailslot : SMB_MailSlot_message(header.unicode, count);
	SMB_MAILSLOT_LANMAN -> lanman   : SMB_MailSlot_message(header.unicode, count);
	SMB_RAP             -> rap      : SMB_Pipe_message(header.unicode, count, sub_cmd);
	SMB_PIPE            -> pipe     : SMB_Pipe_message(header.unicode, count, sub_cmd);
	SMB_UNKNOWN         -> unknown  : bytestring &restofdata;
	default             -> data     : bytestring &restofdata;
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
	pad1                : padding to param_offset - SMB_Header_length;
	parameters          : bytestring &length = param_count;
	pad2                : padding to data_offset - SMB_Header_length;
	data                : SMB_transaction_data(header, data_count, sub_cmd, determine_transaction_type(setup_count, name));
} &let {
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
	sub_cmd             : uint16;

	byte_count          : uint16;
	pad1                : padding to (param_offset - SMB_Header_length);
	parameters          : bytestring &length=byte_count;
	#parameters : case sub_cmd of {
	#	0x0001 -> find_first2     : uint16;
	#	0x0003 -> query_fs_info   : uint16;
	#	0x0005 -> query_path_info : uint16;
	#	0x0006 -> set_path_info   : uint16;
	#	0x0008 -> set_file_info   : uint16;
	#	
	#};
	pad2                : padding to (data_offset - SMB_Header_length);
	data                : bytestring &length=data_count;
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
	parameters          : bytestring &length = byte_count;
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
