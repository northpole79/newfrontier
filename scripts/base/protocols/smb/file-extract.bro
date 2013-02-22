
module SMB;

export {
	redef record FileInfo += {
		extract        : bool &default=F;
		extracted_file : file &log &optional;
	};

	const extract_filenames = /NO_DEFAULT/ &redef;
	const extract_filetypes = /NO_DEFAULT/ &redef;
}

global file_num = 0;

event smb_nt_create_andx_request(c: connection, hdr: SMBHeader, name: string) &priority=3
	{
	if ( extract_filenames in name )
		c$smb$current_file$extract=T;
	}

event smb_read_andx_response(c: connection, hdr: SMBHeader, data: string) &priority=-3
	{
	if ( c$smb$current_file$extract )
		{
		if ( ! c$smb$current_file?$extracted_file )
			{
			++file_num;
			c$smb$current_file$extracted_file = open(fmt("smb-read-extract-%d-%s", file_num, gsub(c$smb$current_file$name, /[^\.a-zA-Z0-9]/, "_")));
			enable_raw_output(c$smb$current_file$extracted_file);
			}
		
		print c$smb$current_file$extracted_file, data;
		}
	}

event smb_write_andx_request(c: connection, hdr: SMBHeader, file_id: count, offset: count, data: string) &priority=3
	{
	if ( c$smb$current_file$extract )
		{
		if ( ! c$smb$current_file?$extracted_file )
			{
			++file_num;
			c$smb$current_file$extracted_file = open(fmt("smb-write-extract-%d-%s", file_num, gsub(c$smb$current_file$name, /[^\.a-zA-Z0-9]/, "_")));
			enable_raw_output(c$smb$current_file$extracted_file);
			}
		
		print c$smb$current_file$extracted_file, data;
		}
	}