// See the file "COPYING" in the main distribution directory for copyright.
//
// Log writer for STOMP.

#ifndef LOGGING_WRITER_STOMP_H
#define LOGGING_WRITER_STOMP_H

#include <activemq/core/ActiveMQConnectionFactory.h>
#include <cms/Connection.h>
#include <cms/Session.h>
#include <cms/MapMessage.h>

#include "../WriterBackend.h"
#include "threading/formatters/Ascii.h"

namespace logging { namespace writer {

class Stomp : public WriterBackend {
public:
	Stomp(WriterFrontend* frontend);
	~Stomp();

	static bool LibraryInit();

	static WriterBackend* Instantiate(WriterFrontend* frontend)
		{ return new Stomp(frontend); }

protected:
	virtual bool DoInit(const WriterInfo& info, int num_fields,
			    const threading::Field* const* fields);
	virtual bool DoWrite(int num_fields, const threading::Field* const* fields,
			     threading::Value** vals);
	virtual bool DoSetBuf(bool enabled)	{ return true; }
	virtual bool DoRotate(const char* rotated_path, double open,
			      double close, bool terminating);
	virtual bool DoFlush(double network_time) { return true; }
	virtual bool DoFinish(double network_time);
	virtual bool DoHeartbeat(double network_time, double current_time)	{ return true; }	

private:
	bool DoWriteOne(ODesc* desc, threading::Value* val, const threading::Field* field);
	void ValToAscii(ODesc* desc, threading::Value* val);
	bool AddParams(threading::Value* val, cms::MapMessage* m, int pos);
	
	cms::Connection* connection;
	cms::Session* session;
	cms::Destination* destination;
	cms::MessageProducer* producer;

	// Options set from the script-level.
	string set_separator;
	string empty_field;
	string unset_field;

	threading::formatter::Formatter* formatter;
};

}
}


#endif
