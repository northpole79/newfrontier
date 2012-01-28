%include binpac.pac
%include bro.pac

type uint24 = record {
	byte1 : uint8;
	byte2 : uint8;
	byte3 : uint8;
};

function to_int(num: uint24): uint32
	%{
	return (num->byte1() << 16) | (num->byte2() << 8) | num->byte3();
	%}

analyzer SMB withcontext {
	connection:  SMB_Conn;
	flow:        SMB_Flow;
};

connection SMB_Conn(bro_analyzer: BroAnalyzer) {
	upflow   = SMB_Flow(true);
	downflow = SMB_Flow(false);
};

%include smb-protocol.pac
%include smb-mailslot.pac
%include smb-pipe.pac
%include smb2-protocol.pac

flow SMB_Flow(is_orig: bool) {
	flowunit = SMB_TCP(is_orig) withcontext(connection, this);
};

%include smb-analyzer.pac
%include smb2-analyzer.pac