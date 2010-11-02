# $Id:$

redef capture_filters += { ["smb"] = "port 445 or port 139" };
global smb_ports = { 445/tcp, 139/tcp } &redef;
redef dpd_config += { [ANALYZER_SMB] = [$ports = smb_ports] };

module SMB;

export {
	const log = open_log_file("smb") &raw_output;

	const command_names: table[count] of string = {
		[0x00] = "create_directory",
		[0x01] = "delete_directory",
		[0x02] = "open",
		[0x03] = "create",
		[0x04] = "close",
		[0x05] = "flush",
		[0x06] = "delete",
		[0x07] = "rename",
		[0x08] = "query_information",
		[0x09] = "set_information",
		[0x0A] = "read",
		[0x0B] = "write",
		[0x0C] = "lock_byte_range",
		[0x0D] = "unlock_byte_range",
		[0x0E] = "create_temporary",
		[0x0F] = "create_new",
		[0x10] = "check_directory",
		[0x11] = "process_exit",
		[0x12] = "seek",
		[0x13] = "lock_and_read",
		[0x14] = "write_and_unlock",
		[0x1A] = "read_raw",
		[0x1B] = "read_mpx",
		[0x1C] = "read_mpx_secondary",
		[0x1D] = "write_raw",
		[0x1E] = "write_mpx",
		[0x1F] = "write_mpx_secondary",
		[0x20] = "write_complete",
		[0x21] = "query_server",
		[0x22] = "set_information2",
		[0x23] = "query_information2",
		[0x24] = "locking_andx",
		[0x25] = "transaction",
		[0x26] = "transaction_secondary",
		[0x27] = "ioctl",
		[0x28] = "ioctl_secondary",
		[0x29] = "copy",
		[0x2A] = "move",
		[0x2B] = "echo",
		[0x2C] = "write_and_close",
		[0x2D] = "open_andx",
		[0x2E] = "read_andx",
		[0x2F] = "write_andx",
		[0x30] = "new_file_size",
		[0x31] = "close_and_tree_disc",
		[0x32] = "transaction2",
		[0x33] = "transaction2_secondary",
		[0x34] = "find_close2",
		[0x35] = "find_notify_close",
		[0x70] = "tree_connect",
		[0x71] = "tree_disconnect",
		[0x72] = "negotiate",
		[0x73] = "session_setup_andx",
		[0x74] = "logoff_andx",
		[0x75] = "tree_connect_andx",
		[0x80] = "query_information_disk",
		[0x81] = "search",
		[0x82] = "find",
		[0x83] = "find_unique",
		[0x84] = "find_close",
		[0xA0] = "nt_transact",
		[0xA1] = "nt_transact_secondary",
		[0xA2] = "nt_create_andx",
		[0xA4] = "nt_cancel",
		[0xA5] = "nt_rename",
		[0xC0] = "open_print_file",
		[0xC1] = "write_print_file",
		[0xC2] = "close_print_file",
		[0xC3] = "get_print_queue",
		[0xD8] = "read_bulk",
		[0xD9] = "write_bulk",
		[0xDA] = "write_bulk_data",
	};
}

global map_fid_to_filename: table[count] of string;


event smb_message(c: connection, hdr: smb_hdr, is_orig: bool, body: string)
	{
	print log, cat_sep("\t", "\\N", network_time(),
	                                command_names[hdr$command],
	                                is_orig ? "REQUEST " : "RESPONSE",
	                                sub_bytes(body, 0, 100));
	}
