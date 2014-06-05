##! Detect the OpenSSL CCS attack

@load base/protocols/ssl
@load base/frameworks/notice

module OpenSSL_CCS;

export {
	redef enum Notice::Type += {
		## Indicates that someone performed a CCS MITM attack (...or scan...) on a host
		SSL_CCS_Attack_Detected
	};
}

redef record SSL::Info += {
	resumed_session: bool &default=F;
	client_key_exchange_seen: bool &default=F;
	server_key_exchange_seen: bool &default=F;
	certificate_seen: bool &default=F;
};

# We want to detect the attack from both sides, server and client.

event ssl_handshake_message(c: connection, is_orig: bool, msg_type: count, length: count) &priority=3
	{
	if ( ! c?$ssl )
		return;

	if ( is_orig && msg_type == SSL::CLIENT_KEY_EXCHANGE )
		c$ssl$client_key_exchange_seen = T;

	if ( !is_orig && msg_type == SSL::CERTIFICATE )
		c$ssl$certificate_seen = T;

	if ( !is_orig && msg_type == SSL::SERVER_KEY_EXCHANGE )
		c$ssl$server_key_exchange_seen = T;
	}

event ssl_server_hello(c: connection, version: count, possible_ts: time, server_random: string, session_id: string, cipher: count, comp_method: count) &priority=3
	{
	if ( !c?$ssl )
		return;

	if ( c$ssl?$session_id && c$ssl$session_id == bytestring_to_hexstr(session_id) )
		c$ssl$resumed_session = T;

	# for anon cipher suites we do not expect a certificate. Pretend we saw it.
	if ( /_ANON_/ in c$ssl$cipher )
		c$ssl$certificate_seen = T;

	# we will usually only see a server-key-exchange when negotiating dh/dhe. Set server_key_exchange_seen to true
	# unless that is the case
	c$ssl$server_key_exchange_seen = T;
	if ( /_(EC)?DHE_/ in c$ssl$cipher )
		c$ssl$server_key_exchange_seen = F;
	}

event ssl_change_cipher_spec(c: connection, is_orig: bool) &priority=3
	{
	if ( !c?$ssl )
		return;

	# Ignore if we negotiated a NULL cipher or the session is resumed
	if ( /_NULL/ in c$ssl$cipher || c$ssl$resumed_session )
		return;

	# On the server-side, an attack is in process if we see a ccs before the client key exchange
	# message was seen.
	if ( is_orig && !c$ssl$client_key_exchange_seen )
		NOTICE([$note=OpenSSL_CCS::SSL_CCS_Attack_Detected,
			$msg="An OpenSSL CCS attack on a server was detected. ChangeCipherSpec seen before ClientKeyExchange",
			$conn=c, $identifier=c$uid]);

	# On the client-side, an attack is in process if we see a ccs before the certificate or before
	# the server key-exchange message. (Both are not always necessary but set to true in those case).
	else if ( !is_orig && ( !c$ssl$certificate_seen || !c$ssl$server_key_exchange_seen ) )
		NOTICE([$note=OpenSSL_CCS::SSL_CCS_Attack_Detected,
			$msg=fmt("An OpenSSL CCS attack on a client was detected. ChangeCipherSpec seen before certificate/server_key_exhange (%d/%d)",
			c$ssl$certificate_seen, c$ssl$server_key_exchange_seen),
			$conn=c, $identifier=c$uid]);
	}
