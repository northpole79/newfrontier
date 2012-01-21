// See the file "COPYING" in the main distribution directory for copyright.

#ifndef smb_h
#define smb_h

#include "TCP.h"

#include "smb_pac.h"

enum IPC_named_pipe {
	IPC_NONE,
	IPC_LOCATOR,
	IPC_EPMAPPER,
	IPC_SAMR,	// Security Account Manager
};

class SMB_Body : public binpac::SMB::SMB_body {
public:
	SMB_Analyzer_binpac(Connection* conn);
	virtual ~SMB_Analyzer_binpac();

	virtual void Done();
	virtual void DeliverStream(int len, const u_char* data, bool orig);
	virtual void Undelivered(int seq, int len, bool orig);
	virtual void EndpointEOF(TCP_Reassembler* endp);

	static Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new SMB_Analyzer_binpac(conn); }

	static bool Available()
        { return true; }

protected:
	binpac::SMB::SMB_Conn* interp;
};

#endif
