

refine connection SMB_Conn += {
	#flowunit = SMB2_PDU(is_orig) withcontext (connection, this);
		
	#function proc_smb2_message_request(pdu: SMB2_PDU) : bool
	#	%{
	#	//printf("proc_smb2_message_request!!!\n");
	#	return true;
	#	%}
	
	function proc_smb2_negotiate_request(req: SMB2_negotiate_request) : bool
		%{
		//printf("negotiate_request!\n");
		//if ( ${req.dialect_count} != 0 )
		//	connection()->bro_analyzer()->Weird("SMB2 wrong dialect count for Protocol Negotiate request!");
		//if ( ${req.capabilities} != 0 )
		//	connection()->bro_analyzer()->Weird("SMB2 invalid capabilities for Protocol Negotiate request!");		
		return true;
		%}
		
	function proc_smb2_negotiate_response(header: SMB2_Header, res: SMB2_negotiate_response) : bool
		%{
		//printf(" hey! %s - %d - %d hey!\n", (char*)${header.protocol}.begin(), ${header.process_id}, ${header.credit_charge});
		//Val *credit_charge = new Val(${header.credit_charge}, TYPE_COUNT);
		//
		//StringVal *cg = new StringVal(${res.server_guid}.length(), (const char*) ${res.server_guid}.begin());
		//BifEvent::generate_smb2_negotiate_response(connection()->bro_analyzer(),
		//                                           connection()->bro_analyzer()->Conn(),
		//                                           cg, credit_charge->AsCount());
		return true;
		%}
		
	function proc_smb2_create_request(header: SMB2_Header, req: SMB2_create_request): bool
		%{
		//printf("CREATE REQUEST!!!  %s", ${req.filename.s}->begin());
		return true;
		%}
	
};

#refine typeattr SMB2_PDU += &let {
#	processs_smb2_message_request : bool = $context.flow.proc_smb2_message_request(this);
#}


refine typeattr SMB2_negotiate_request += &let {
#	process_negotiate_request : bool = $context.flow.proc_smb2_negotiate_request(this);
	#test: bool = $context.flow.proc_test();
};

refine typeattr SMB2_negotiate_response += &let {
#	process_negotiate_response : bool = $context.flow.proc_smb2_negotiate_response(header, this);
};

refine typeattr SMB2_create_request += &let {
#	process_create_request : bool = $context.flow.proc_smb2_create_request(header, this);
};