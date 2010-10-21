%include binpac.pac
%include bro.pac

analyzer SMB withcontext {
	connection:  SMB_Conn;
	flow:        SMB_Flow;
};

%include nbss.pac

%include smb-protocol.pac
%include smb-mailslot.pac
%include smb-pipe.pac

%include smb-analyzer.pac