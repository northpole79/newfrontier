// See the file "COPYING" in the main distribution directory for copyright.
//
// Log writer for STOMP.

#ifndef LOGGING_WRITE_STOMP_H
#define LOGGING_WRITER_STOMP_H

#include <activemq/core/ActiveMQConnectionFactory.h>
#include <cms/Connection.h>
#include <cms/Session.h>
#include <cms/MapMessage.h>

#include "../WriterBackend.h"

namespace logging { namespace writer {

class Stomp : public WriterBackend {
public:
	Stomp(WriterFrontend* frontend);
	~Stomp();

	static bool LibraryInit();

	static WriterBackend* Instantiate(WriterFrontend* frontend)
		{ return new Stomp(frontend); }

protected:
	virtual bool DoInit(string path, int num_fields,
			    const threading::Field* const* fields);
	virtual bool DoWrite(int num_fields, const threading::Field* const* fields,
			     threading::Value** vals);
	virtual bool DoSetBuf(bool enabled);
	virtual bool DoRotate(string rotated_path, double open,
			      double close, bool terminating);
	virtual bool DoFlush();
	virtual bool DoFinish();

private:
	bool DoWriteOne(ODesc* desc, threading::Value* val, const threading::Field* field);
	void ValToAscii(ODesc* desc, threading::Value* val);
	void AddParams(threading::Value* val, cms::MapMessage* m, int pos);
	
	cms::Connection* connection;
	cms::Session* session;
	cms::Destination* destination;
	cms::MessageProducer* producer;

	// Options set from the script-level.
	char* set_separator;
	int set_separator_len;

	
};

}
}


#endif
