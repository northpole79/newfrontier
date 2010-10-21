// See the file "COPYING" in the main distribution directory for copyright.

#ifndef smb2_h
#define smb2_h

#include "TCP.h"

#include "smb2_pac.h"

class SMB2_Analyzer_binpac : public TCP_ApplicationAnalyzer {
public:
	SMB2_Analyzer_binpac(Connection* conn);
	virtual ~SMB2_Analyzer_binpac();

	virtual void Done();
	virtual void DeliverStream(int len, const u_char* data, bool orig);
	virtual void Undelivered(int seq, int len, bool orig);
	virtual void EndpointEOF(TCP_Reassembler* endp);

	static Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new SMB2_Analyzer_binpac(conn); }

	static bool Available()
        { return true; }
	//	{ return (smb2_request || smb2_reply) && FLAGS_use_binpac; }

protected:
	binpac::SMB2::SMB2_Conn* interp;
};

#endif
