// See the file "COPYING" in the main distribution directory for copyright.

#ifndef smb_h
#define smb_h

#include "TCP.h"
#include "RPC.h"
#include "DCE_RPC.h"

#include "smb_pac.h"



class Contents_SMB : public TCP_SupportAnalyzer {
public:
	Contents_SMB(Connection* conn, bool orig);
	~Contents_SMB();

	virtual void DeliverStream(int len, const u_char* data, bool orig);

protected:
	typedef enum {
		WAIT_FOR_HDR,
		WAIT_FOR_DATA
	} state_t;
	typedef enum {
		NEED_RESYNC,
		INSYNC,
	} resync_state_t;
	virtual void Init();
	virtual bool CheckResync(int& len, const u_char*& data, bool orig);
	virtual void Undelivered(int seq, int len, bool orig);
	virtual void NeedResync() {
		resync_state = NEED_RESYNC;
		state = WAIT_FOR_HDR;
	}

	void DeliverSMB(int len, const u_char* data);

	binpac::SMB::SMB_Conn* smb_session;

	RPC_Reasm_Buffer hdr_buf; // Reassembles the NetBIOS length and glue.
	RPC_Reasm_Buffer msg_buf; // Reassembles the SMB message.
	int msg_len;
	int msg_type;
	double first_time;   // timestamp of first packet of current message
	double last_time;    // timestamp of last pakcet of current message
	state_t state;
	resync_state_t resync_state;
};

class SMB_Analyzer : public TCP_ApplicationAnalyzer {
public:
	SMB_Analyzer(Connection* conn);
	virtual ~SMB_Analyzer();
	
	virtual void Done();
	virtual void DeliverStream(int len, const u_char* data, bool orig);
	virtual void Undelivered(int seq, int len, bool orig);
	virtual void EndpointEOF(bool is_orig);

	static Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new SMB_Analyzer(conn); }
	
	static bool Available()
		{ return true; }

protected:
	binpac::SMB::SMB_Conn* interp;
	Contents_SMB* o_smb;
	Contents_SMB* r_smb;
};


#endif
