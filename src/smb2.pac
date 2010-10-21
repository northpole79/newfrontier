%include binpac.pac
%include bro.pac

analyzer SMB2 withcontext {
	connection:	SMB2_Conn;
	flow:		SMB2_Flow;
};

%include nbss.pac

%include smb2-protocol.pac
%include smb2-analyzer.pac
