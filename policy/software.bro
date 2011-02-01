
module Software;

export {
	# Create a new ID for our log stream
	redef enum Logging::ID += { LOG_SOFTWARE };
	type Log: record {
		ts:            time;
		host:          addr;
		endpoint_type: string &default="";
		software:      string &default="";
		version:       software_version;
		description:   string &default="";
		raw_version:   string &default="";
	};
	# This is the prototype for the event that the logging framework tries
	# to generate if there is a handler for it.
	global log: event(rec: Log);
	
	redef enum Notice += { 
		Software_Version_Change,
	};
	
	# Some software is more interesting when the version changes.  This is
	# a set of all software that should raise a notice when a different version
	# is seen.
	const interesting_version_changes: set[string] = {
		"SSH"
	} &redef;
	
	# Raise this event from other scripts when software is discovered.
	# This event is actually defined internally in Bro.
	#global software_version_found: event(c: connection, host: addr, s: software, descr: string);	
	
	# Index is the name of the software.
	type software_set: table[string] of software;
	# The set of software associated with an address.
	# TODO: synchronize this in the cluster setting.
	global host_software: table[addr] of software_set &create_expire=1day;
}

event bro_init()
	{
	Logging::create_stream("software", "Software::Log");
	}

# Compare two versions.
#   Returns -1 for v1 < v2, 0 for v1 == v2, 1 for v1 > v2.
#   If the numerical version numbers match, the addl string
#   is compared lexicographically.
function software_cmp_version(v1: software_version, v2: software_version): int
	{
	if ( v1$major < v2$major )
		return -1;
	if ( v1$major > v2$major )
		return 1;

	if ( v1$minor < v2$minor )
		return -1;
	if ( v1$minor > v2$minor )
		return 1;

	if ( v1$minor2 < v2$minor2 )
		return -1;
	if ( v1$minor2 > v2$minor2 )
		return 1;

	return strcmp(v1$addl, v2$addl);
	}

# Convert a version into a string "a.b.c-x".
function software_fmt_version(v: software_version): string
	{
	return fmt("%s%s%s%s",
	           v$major >= 0  ? fmt("%d", v$major)   : "",
	           v$minor >= 0  ? fmt(".%d", v$minor)  : "",
	           v$minor2 >= 0 ? fmt(".%d", v$minor2) : "",
	           v$addl != ""  ? fmt("-%s", v$addl)   : "");
	}

# Convert a software into a string "name a.b.cx".
function software_fmt(s: software): string
	{
	return fmt("%s %s", s$name, software_fmt_version(s$version));
	}
	
function software_endpoint_type(c: connection, host: addr): string
	{
	return fmt("%s %s", host, (host == c$id$orig_h ? "client" : "server"));
	}
	
event software_new(c: connection, host: addr, s: software, descr: string, raw_version: string)
	{
	local ept = "";
	if ( s$?type )
		ept = s$type;
	else
		ept = software_endpoint_type(c, host);
	
	Logging::log("software", [$ts=network_time(),
	                          $host=host,
	                          $endpoint_type=ept,
	                          $software=s$name,
	                          $version=software_fmt_version(s$version),
	                          $description=descr,
	                          $raw_version=raw_version]);
	}

# Insert a mapping into the table
# Overides old entries for the same software and generates events if needed.
event software_version_found(c: connection, host: addr, s: software, descr: string, raw_version: string)
	{
	# Host already known?
	if ( host !in host_software )
		host_software[host] = table();

	local hs = host_software[host];
	if ( s$name !in hs )
		{
		event software_new(c, host, s, descr, raw_version);
		return;
		}
		
	local old = hs[s$name];

	# Is it a different version?
	if ( software_cmp_version(old$version, s$version) != 0 )
		{
		# Is it a potentially interesting version change?
		if ( s$name in interesting_version_changes )
			{
			local msg = fmt("%.6f %s switched from %s to %s (%s)",
			                network_time(), software_endpoint_type(c, host),
			                software_fmt_version(old$version),
			                software_fmt(s), descr);
			NOTICE([$note=Software_Version_Change,
			        $msg=msg, $sub=software_fmt(s), $conn=c]);
			}

		event software_new(c, host, s, descr, raw_version);
		}
	}

	hs[s$name] = s;
	}
