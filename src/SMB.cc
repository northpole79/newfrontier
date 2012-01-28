// See the file "COPYING" in the main distribution directory for copyright.

#include "SMB.h"
#include "Val.h"
#include "Reporter.h"
#include "TCP_Reassembler.h"

#define SMB_MAX_LEN (1<<17)

SMB_Analyzer::SMB_Analyzer(Connection *conn)
: TCP_ApplicationAnalyzer(AnalyzerTag::SMB, conn)
	{
	interp = new binpac::SMB::SMB_Conn(this);
}

SMB_Analyzer::~SMB_Analyzer()
	{
	delete interp;
	}

void SMB_Analyzer::Done()
	{
	TCP_ApplicationAnalyzer::Done();

	interp->FlowEOF(true);
	interp->FlowEOF(false);
	}

void SMB_Analyzer::EndpointEOF(TCP_Reassembler* endp)
	{
	TCP_ApplicationAnalyzer::EndpointEOF(endp);
	interp->FlowEOF(endp->IsOrig());
	}
	
void SMB_Analyzer::Undelivered(int seq, int len, bool orig)
	{
	TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);
	interp->NewGap(orig, len);
	}

void SMB_Analyzer::DeliverStream(int len, const u_char* data, bool orig)
	{
	TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);

	assert(TCP());

	if ( TCP()->IsPartial() )
		// punt on partial.
		return;

	interp->NewData(orig, data, data + len);

	//try
	//	{
	//	const u_char* data_start = data;
	//	const u_char* data_end = data + len;
    //
	//	binpac::SMB::SMB_header hdr;
	//	int hdr_len = hdr.Parse(data, data_end);
    //
	//	data += hdr_len;
    //
	//	int next_command = hdr.command();
    //
	//	while ( data < data_end )
	//		{
	//		SMB_Body body(data, data_end);
	//		set_andx(is_orig, 0);
	//		ParseMessage(is_orig, next_command, hdr, body);
    //
	//		int next = AndxOffset(is_orig, next_command);
	//		if ( next <= 0 )
	//			break;
    //
	//		//Weird(fmt("ANDX! at %d", next));
	//		const u_char* tmp = data_start + next;
	//		if ( data_start + next < data + body.length() )
	//			{
	//			Weird(fmt("ANDX buffer overlapping: next = %d, buffer_end = %" PRIuPTR, next, data + body.length() - data_start));
	//			break;
	//			}
    //
	//		data = data_start + next;
	//		}
	//	}
	//catch ( const binpac::Exception& e )
	//	{
	//	analyzer->Weird(e.msg().c_str());
	//	}
	}







Contents_SMB::Contents_SMB(Connection* conn, bool orig)
: TCP_SupportAnalyzer(AnalyzerTag::Contents_SMB, conn, orig)
	{
	state = WAIT_FOR_HDR;
	resync_state = INSYNC;
	first_time = last_time = 0.0;
	hdr_buf.Init(4,4);
	msg_len = 0;
	msg_type = 0;
}

void Contents_SMB::Init()
	{
	TCP_SupportAnalyzer::Init();

	NeedResync();
	}

Contents_SMB::~Contents_SMB()
	{
	}


void Contents_SMB::Undelivered(int seq, int len, bool orig)
	{
	TCP_SupportAnalyzer::Undelivered(seq, len, orig);
	NeedResync();
	}

void Contents_SMB::DeliverSMB(int len, const u_char* data)
	{
	// Check the 4-byte header.
	if ( strncmp((const char*) data+4, "\xffSMB", 4) != 0 )
		{
		Conn()->Weird(fmt("SMB-over-TCP header error: %02x %05x, >>\\x%02x%c%c%c<<",
			//dshdr[0], dshdr[1], dshdr[2], dshdr[3],
			msg_type, msg_len,
			data[0], data[1], data[2], data[3]));
		NeedResync();
		}
	else
		{
		printf("actually delivering smb!\n");
		ForwardStream(len, data, IsOrig());
		}
	}

bool Contents_SMB::CheckResync(int& len, const u_char*& data, bool orig)
	{
	if (resync_state == INSYNC)
		return true;

	// This is an attempt to re-synchronize the stream after a content gap.  
	// Returns true if we are in sync. 
	// Returns false otherwise (we are in resync mode)
	//
	// We try to look for the beginning of a SMB message, assuming 
	// SMB messages start at packet boundaries (though they may span 
	// over multiple packets) (note that the data* of DeliverStream()
	// usually starts at a packet boundrary). 
	//

	// Now lets see whether data points to the beginning of a
	// SMB message. If the resync processs is successful, we should
	// be at the beginning of a frame.

	
	if ( len < 36 )
		{
		// Ignore small chunks. 
		// 4 byte NetBIOS header (or length field) + 32 Byte SMB header
		Conn()->Weird(fmt("SMB resync: discard %d bytes\n",
					len));
		NeedResync();
		return false;
		}


	const u_char *xdata = data;
	int xlen = len;
	bool discard_this_chunk = false;

	// Check if it's a data message
	if (xdata[0]!=0x00)
		discard_this_chunk = true;

	// Check if the flags / high-byte of the message length is < 1
	if (xdata[1] > 1)
		discard_this_chunk = true;

	// check if the SMB header starts with \xFFSMB
	if (strncmp((const char*) (xdata+4), "\xffSMB", 4)!=0)
		discard_this_chunk = true;

	if (discard_this_chunk)
		{
		NeedResync();
		return false;
		}

	resync_state = INSYNC;
	first_time = last_time = 0.0;
	hdr_buf.Init(4,4);
	msg_len = 0;
	msg_type = 0;
	return true;
	}

void Contents_SMB::DeliverStream(int len, const u_char* data, bool orig)
	{
	TCP_SupportAnalyzer::DeliverStream(len, data, orig);
	
	if (!CheckResync(len, data, orig))
		return;   // Not in sync yet. Still resyncing

	while ( len > 0 )
		{
		switch (state) {
		case WAIT_FOR_HDR:
			{
			// We have the 4 bytes header now
			if (data[1] > 1) 
				Conn()->Weird(fmt("NetBIOS session flags > 1: %d", data[1]));
			msg_len = 0;
			msg_type = data[0];
			for ( int i =1; i < 4; i++)
				msg_len = (msg_len << 8) + data[i];
			msg_len+=4;
			msg_buf.Init(SMB_MAX_LEN+4, msg_len);
			state = WAIT_FOR_DATA;
			}
			break;
		case WAIT_FOR_DATA:
			{
			bool got_all_data = msg_buf.ConsumeChunk(data, len);
			if ( got_all_data && msg_buf.GetFill() >= msg_len )
				{
				printf("msg_buf: %s\n", msg_buf.GetBuf());
				const u_char *dummy_p = msg_buf.GetBuf();
				int dummy_len = (int) msg_buf.GetFill();
				DeliverSMB(dummy_len, dummy_p);
				
				state = WAIT_FOR_HDR;
				hdr_buf.Init(4,4);
			}
			}
			break;
		} // end switch
		} // end while
	}
