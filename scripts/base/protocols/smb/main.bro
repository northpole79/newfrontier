module SMB;

export {
	redef enum Log::ID += { LOG, FILES_LOG };
	type Info: record {
		pid            : count  &log;
		mid            : count  &log;
		cmd            : count  &log;
		cmdstr         : string &log;
		
		fidstr         : string &log;
		# for read/writes: number of bytes read/written and offset
		file_payload   : count  &log;
		file_offset    : count  &log;
		
		cmdid          : count  &log;
		
		req_first_time : time   &optional &log;
		req_last_time  : time   &optional &log;
		req_body_len   : count  &optional &log;

		rep_first_time : time   &optional &log;
		rep_last_time  : time   &optional &log;
		rep_body_len   : count  &optional &log;

		done           : bool   &default=F;
		pending_files  : table[count] of string &default=table();
		files          : table[count] of string &default=table();
	};

	type FileInfo: record {
		
	};

	redef record connection += {
		smb              : Info                        &optional;
		smb_pending_cmds : table[count, count] of Info &default=table();
	};
}

redef capture_filters += { ["smb"] = "port 445" };
global ports = { 139/tcp, 445/tcp } &redef;
redef dpd_config += { [ANALYZER_SMB] = [$ports = ports] };

event bro_init() &priority=5
	{
	Log::create_stream(LOG, [$columns=SMB::Info]);
	Log::create_stream(FILES_LOG, [$columns=SMB::FileInfo]);
	}

function set_cmd(c: connection, hdr: SMBHeader)
	{
	if ( ! c?$smb )
		{
		local info: Info;
		
		info$cmd = hdr$command;
		info$pid = hdr$pid;
		info$mid = hdr$mid;
		info$cmdstr = "";
		
		info$fidstr = "FIDxx"; 
		info$file_payload = 0;
		info$file_offset = 0;
		#info$cmdid = nextcmdid;
		#++nextcmdid;
		
		#info$req_first_time = hdr$first_time;
		#info$req_last_time = hdr$last_time;
		#info$req_body_len = body_len;
		
		info$rep_first_time = double_to_time(0.0);
		info$rep_last_time = double_to_time(0.0);
		info$rep_body_len = 0;
		
		info$done = F;
		
		c$smb = info;
		}
	}
	
event smb_nt_create_andx_request(c: connection, hdr: SMBHeader, name: string)
	{
	#print name;
	c$smb$pending_files[|c$smb$pending_files|] = name;
	#print name;
	}

event smb_nt_create_andx_response(c: connection, hdr: SMBHeader, fid: count)
	{
	#print fid;
	}

event smb_read_andx_request(c: connection, hdr: SMBHeader, file_id: count, offset: count)
	{
	#print "read andx request";
	#print hdr;
	}
	
global open_files: table[count, count, count, count] of file;
global file_num = 0;

event smb_read_andx_response(c: connection, hdr: SMBHeader, data: string)
	{
	#print "read andx response";
	#print data;
	if ( [hdr$tid, hdr$pid, hdr$uid, hdr$mid] !in open_files )
		{
		++file_num;
		open_files[hdr$tid, hdr$pid, hdr$uid, hdr$mid] = open(fmt("smb-read-extract-%d", file_num));
		enable_raw_output(open_files[hdr$tid, hdr$pid, hdr$uid, hdr$mid]);
		}
		
	print open_files[hdr$tid, hdr$pid, hdr$uid, hdr$mid], data;
	}

event smb_write_andx_request(c: connection, hdr: SMBHeader, data: string)
	{
	#print "write andx request";
	#print hdr;
	#print |data|;
	#print data;
	if ( [hdr$tid, hdr$pid, hdr$uid, hdr$mid] !in open_files )
		{
		++file_num;
		open_files[hdr$tid, hdr$pid, hdr$uid, hdr$mid] = open(fmt("smb-write-extract-%d", file_num));
		enable_raw_output(open_files[hdr$tid, hdr$pid, hdr$uid, hdr$mid]);
		}
		
	print open_files[hdr$tid, hdr$pid, hdr$uid, hdr$mid], data;
	
	}
	
event smb_write_andx_response(c: connection, hdr: SMBHeader, written_bytes: count)
	{
	#print "write andx response";
	#print hdr;
	#print written_bytes;
	}
	
	
#event smb_message(c: connection, hdr: smb_hdr, is_orig: bool, cmd: string, body_length: count, body: string) 
#	{
#	print hdr;
#	}
	
	
#event smb_com_read_andx(c: connection, hdr: smb_hdr, fid: count, offset: count)
#	{
#	print fid;
#	}

#event smb_com_read_andx_response(c: connection, hdr: smb_hdr, len: count) 
#	{
#	smb_set_file_payload(c$id, hdr, len);
#	smb_log_cmd2(c, hdr);
#	}
#
#event smb_com_write_andx(c: connection, hdr: smb_hdr, fid: count, offset: count, len: count)
#	{
#	smb_set_fid_offset(c$id, hdr, fid, offset);
#	smb_set_file_payload(c$id, hdr, len);
#	}
#
#event smb_com_write_andx_response(c: connection, hdr: smb_hdr)
#	{
#	smb_log_cmd2(c, hdr);
#	}
#
#
#event smb_com_nt_create_andx(c: connection, hdr: smb_hdr, name: string)
#	{
#	local cmdid = get_cmdid(c$id, hdr);	
#	if (!cmdid)
#		return;  # weird. Should not happen actually.
#	# TODO: could/should check that there isn't a filename already there.
#	smb_filenames[cmdid] = name;
#	}
#
#event smb_com_nt_create_andx_response(c: connection, hdr: smb_hdr, fid: count, size: count) 
#	{
#	# delete any old FID mappings. 
#	delete_fid(c$id, fid);
#	# this will implicitly create a new mapping
#	smb_set_fid_offset(c$id, hdr, fid, 0);
#	local cmdid = get_cmdid(c$id, hdr);	
#	if (!cmdid)
#		return;  # weird. Should not happen actually.
#	if (cmdid !in smb_filenames)
#		return;
#	print smb_files_log, fmt("%.6f %s %d %s", network_time(), get_fid(c$id, fid), 
#			size, smb_filenames[cmdid]);
#	smb_log_cmd2(c, hdr);
#	}
#
#
#event smb_com_close(c: connection, hdr: smb_hdr, fid: count) 
#	{
#	# We first set to fid in the smb_cmd_info record, so it will be 
#	# printed.
#	smb_set_fid_offset(c$id, hdr, fid, 0);
#	# Now we delete the fid mapping since the file has been closed.
#	delete_fid(c$id, fid);
#	}
#
#event smb_error(c: connection, hdr: smb_hdr, cmd: count, cmd_str: string, errtype: count, error: count) 
#	{
#	print smb_log, fmt("ERROR: %s %s (0x%2x): %d %08x", id_string(c$id), cmd_str, cmd, errtype, error);
#	}
