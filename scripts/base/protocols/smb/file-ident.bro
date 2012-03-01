
module SMB;

export {
	redef record FileInfo += {
		mime_type : string &log &optional;
		mime_desc : string &log &optional;
	};
}

event smb_read_andx_response(c: connection, hdr: SMBHeader, data: string) &priority=4
	{
	if ( c$smb$current_file$current_byte == 0 )
		{
		c$smb$current_file$mime_type = identify_data(data, T);
		c$smb$current_file$mime_desc = identify_data(data, F);
		}
	}

event smb_write_andx_request(c: connection, hdr: SMBHeader, file_id: count, offset: count, data: string) &priority=4
	{
	if ( c$smb$current_file$current_byte == 0 )
		{
		c$smb$current_file$mime_type = identify_data(data, T);
		c$smb$current_file$mime_desc = identify_data(data, F);
		}
	}
