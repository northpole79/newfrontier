module SMB;

export {
	redef enum Log::ID += { LOG, FILES_LOG };
	
	## If this is set to F, any commands involving alternate data streams
	## will be ignored.
	const ignore_ADS = T &redef;
	
	type FileInfo: record {
		## Time when the file was first discovered.
		ts             : time    &log;
		uid            : string  &log;
		id             : conn_id &log;
		
		## Path pulled from the tree this file was transferred to or from.
		path           : string  &log &optional;
		## Filename if one was seen.
		name           : string  &log &optional;
		## Total size of the file.
		size           : count   &log &default=0;
		## Last time this file was modified.
		last_modified  : time    &log &optional;
		
		read_chunks    : count   &log &default=0;
		write_chunks   : count   &log &default=0;
		
		## Indicates if the file was seen in whole.
		complete       : bool    &log &default=F;
		## Indicates if the file linearly transferred.
		linear         : bool    &log &default=F;
		
		## ID referencing this file.
		fid            : count &optional;
		## Track where the last seen byte in the file was.
		current_byte   : count &default=0;
	};
	
	type TreeInfo: record {
		## Name of the tree path.
		path               : string &log &optional;
		
		service            : string &log &optional;
		
		native_file_system : string &log &optional;
	};
	
	type CmdInfo: record {
		## The command.
		command              : string   &log &optional;
		
		## If the command referenced a file, store it here.
		referenced_file      : FileInfo &optional;
		## If the command referenced a tree, store it here.
		referenced_tree      : TreeInfo &optional;
	};
	
	type Info: record {
		## A reference to the current command.
		current_cmd    : CmdInfo     &log &optional;
	
		## A reference to the current file.
		current_file   : FileInfo    &log &optional;
		
		## A reference to the current tree.
		current_tree   : TreeInfo    &log &optional;
		
		## Indexed on MID to map responses to requests.
		pending_cmds   : table[count] of CmdInfo    &optional;
		## File map to retrieve file information based on the file ID.
		fid_map        : table[count] of FileInfo   &optional;
		## Tree map to retrieve tree information based on the tree ID.
		tid_map        : table[count] of TreeInfo   &optional;
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

function set_current_file(smb: Info, file_id: count)
	{
	if ( file_id !in smb$fid_map )
		{
		smb$fid_map[file_id] = smb$current_cmd$referenced_file;
		smb$fid_map[file_id]$fid = file_id;
		}
	
	smb$current_file = smb$fid_map[file_id];
	}

event smb_message(c: connection, hdr: SMBHeader, is_orig: bool) &priority=5
	{
	if ( ! c?$smb )
		{
		local info: Info;
		info$fid_map = table();
		info$tid_map = table();
		info$pending_cmds = table();
		c$smb = info;
		}
	
	local tid = hdr$tid;
	local pid = hdr$pid;
	local uid = hdr$uid;
	local mid = hdr$mid;
	
	if ( tid !in c$smb$tid_map )
		{
		local tmp_tree: TreeInfo;
		c$smb$tid_map[tid] = tmp_tree;
		}
	c$smb$current_tree = c$smb$tid_map[tid];
	
	if ( mid !in c$smb$pending_cmds )
		{
		local tmp_cmd: CmdInfo;
		tmp_cmd$command = commands[hdr$command];
		
		local tmp_file: FileInfo;
		tmp_file$ts = network_time();
		tmp_cmd$referenced_file = tmp_file;
		tmp_cmd$referenced_tree = c$smb$current_tree;
		
		c$smb$pending_cmds[mid] = tmp_cmd;
	}
	c$smb$current_cmd = c$smb$pending_cmds[mid];
}

event smb_message(c: connection, hdr: SMBHeader, is_orig: bool) &priority=-5
	{
	if ( !is_orig )
		# This is a response and the command is no longer pending
		# so let's get rid of it.
		delete c$smb$pending_cmds[hdr$mid];
	}

event smb_tree_connect_andx_request(c: connection, hdr: SMBHeader, path: string, service: string) &priority=5
	{
	c$smb$current_cmd$referenced_tree$path = path;
	c$smb$current_cmd$referenced_tree$service = service;
	}

event smb_tree_connect_andx_response(c: connection, hdr: SMBHeader, service: string, native_file_system: string) &priority=5
	{
	c$smb$current_cmd$referenced_tree$native_file_system = native_file_system;
	c$smb$current_tree = c$smb$current_cmd$referenced_tree;
	c$smb$tid_map[hdr$tid] = c$smb$current_tree;
}

event smb_nt_create_andx_request(c: connection, hdr: SMBHeader, name: string) &priority=5
	{
	c$smb$current_cmd$referenced_file$name = name;
	c$smb$current_file = c$smb$current_cmd$referenced_file;
	}

event smb_nt_create_andx_response(c: connection, hdr: SMBHeader, file_attrs: SMBFileAttrs) &priority=5
	{
	c$smb$current_file$fid = file_attrs$fid;
	c$smb$current_file$size = file_attrs$end_of_file;
	c$smb$current_file$last_modified = file_attrs$last_change_ts;
	
	# We can identify the file by its file id now so let's stick it 
	# in the file map.
	c$smb$fid_map[file_attrs$fid] = c$smb$current_file;
}
	
event smb_read_andx_request(c: connection, hdr: SMBHeader, file_id: count, offset: count, length: count) &priority=5
	{
	set_current_file(c$smb, file_id);
	++c$smb$current_file$read_chunks;
	}
	
event smb_read_andx_response(c: connection, hdr: SMBHeader, data: string) &priority=5
	{
	c$smb$current_cmd$referenced_file$current_byte += |data|;
	}

event smb_write_andx_request(c: connection, hdr: SMBHeader, file_id: count, offset: count, data: string) &priority=5
	{
	set_current_file(c$smb, file_id);
	}
	
event smb_write_andx_request(c: connection, hdr: SMBHeader, file_id: count, offset: count, data: string) &priority=-5
	{
	++c$smb$current_file$write_chunks;
	c$smb$current_file$current_byte += |data|;
	}

event smb_write_andx_response(c: connection, hdr: SMBHeader, written_bytes: count) &priority=5
	{
	}

event smb_close_request(c: connection, hdr: SMBHeader, file_id: count) &priority=-5
	{
	set_current_file(c$smb, file_id);
		
	if ( file_id in c$smb$fid_map )
		{
		local fl = c$smb$fid_map[file_id];
		fl$uid = c$uid;
		fl$id = c$id;
		# Need to check for existence of path in case tree connect message wasn't seen.
		if ( c$smb$current_tree?$path )
		fl$path = c$smb$current_tree$path;
		delete c$smb$fid_map[file_id];
		Log::write(FILES_LOG, c$smb$current_file);
		}
	else
		{
		print "attempting to close an unknown file!";
		}
	}
