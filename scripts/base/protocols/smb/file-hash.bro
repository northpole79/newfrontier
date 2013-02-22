##! Calculate hashes for SMB transfers.

@load ./file-ident

module SMB;

export {
	redef record FileInfo += {
		## MD5 sum for a file transferred over HTTP calculated from the 
		## response body.
		md5:             string   &log &optional;
		
		## This value can be set per-transfer to determine per request
		## if a file should have an MD5 sum generated.  It must be
		## set to T at the time of or before the first chunk of body data.
		calc_md5:        bool     &default=F;
		
		## Indicates if an MD5 sum is being calculated for the current 
		## request/response pair.
		md5_handle: opaque of md5   &optional;
	};
	
	## Generate MD5 sums for these filetypes.
	const generate_md5 = /.*/ | /application\/x-dosexec/    # Windows and DOS executables
	                   | /application\/x-executable/ # *NIX executable binary
	                   &redef;
}

function hash_file(c: connection, hdr: SMBHeader, data: string)
	{
	local current_file = c$smb$current_file;
	
	if ( current_file$current_byte == 0 )
		{
		if ( current_file$calc_md5 || 
		     (current_file?$mime_type && generate_md5 in current_file$mime_type) )
			{
			current_file$md5_handle = md5_hash_init();
			}
		}
		
	if ( current_file?$md5_handle )
		md5_hash_update(current_file$md5_handle, data);
	}

event smb_read_andx_response(c: connection, hdr: SMBHeader, data: string) &priority=3
	{
	hash_file(c, hdr, data);
	}

event smb_write_andx_request(c: connection, hdr: SMBHeader, file_id: count, offset: count, data: string) &priority=3
	{
	hash_file(c, hdr, data);
	}

event smb_close_request(c: connection, hdr: SMBHeader, file_id: count) &priority=-3
	{
	local current_file = c$smb$current_file;
	
	if ( current_file?$md5_handle )
		current_file$md5 = md5_hash_finish(current_file$md5_handle);
	}



## In the event of a content gap during a file transfer, detect the state for
## the MD5 sum calculation and stop calculating the MD5 since it would be 
## incorrect anyway.
#event content_gap(c: connection, is_orig: bool, seq: count, length: count) &priority=5
#	{
#	if ( is_orig || ! c?$http || ! c$http$calculating_md5 ) return;
#	
#	set_state(c, F, is_orig);
#	c$http$calculating_md5 = F;
#	md5_hash_finish(c$id);
#	}

#event connection_state_remove(c: connection) &priority=-5
#	{
#	if ( c?$http_state && 
#	     c$http_state$current_response in c$http_state$pending &&
#	     c$http_state$pending[c$http_state$current_response]$calculating_md5 )
#		{
#		# The MD5 sum isn't going to be saved anywhere since the entire 
#		# body wouldn't have been seen anyway and we'd just be giving an
#		# incorrect MD5 sum.
#		md5_hash_finish(c$id);
#		}
#	}
#