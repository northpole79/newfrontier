#include "SMB2.h"
#include "TCP_Reassembler.h"

SMB2_Analyzer_binpac::SMB2_Analyzer_binpac(Connection *conn)
: TCP_ApplicationAnalyzer(AnalyzerTag::SMB2, conn)
	{
	interp = new binpac::SMB2::SMB2_Conn(this);
	}
 
SMB2_Analyzer_binpac::~SMB2_Analyzer_binpac()
	{
	delete interp;
	}

void SMB2_Analyzer_binpac::Done()
	{
	TCP_ApplicationAnalyzer::Done();

	interp->FlowEOF(true);
	interp->FlowEOF(false);
	}

void SMB2_Analyzer_binpac::EndpointEOF(TCP_Reassembler* endp)
	{
	TCP_ApplicationAnalyzer::EndpointEOF(endp);
	interp->FlowEOF(endp->IsOrig());
	}

void SMB2_Analyzer_binpac::DeliverStream(int len, const u_char* data, bool orig)
	{
	TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);

	assert(TCP());

	if ( TCP()->IsPartial() )
		// punt on partial.
		return;

	interp->NewData(orig, data, data + len);
	}

void SMB2_Analyzer_binpac::Undelivered(int seq, int len, bool orig)
	{
	TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);
	interp->NewGap(orig, len);
	}
