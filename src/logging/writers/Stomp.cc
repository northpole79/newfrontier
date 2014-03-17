// See the file "COPYING" in the main distribution directory for copyright.

#include <activemq/core/ActiveMQConnectionFactory.h>
#include <activemq/library/ActiveMQCPP.h>
#include <cms/Connection.h>
#include <cms/Session.h>
#include <cms/TextMessage.h>
#include <cms/MapMessage.h>
#include <cms/CMSException.h>

#include <string>
#include <errno.h>

#include "NetVar.h"
#include "threading/SerialTypes.h"

#include "Stomp.h"


using namespace logging;
using namespace writer;
using namespace activemq::core;
using namespace cms;
using namespace threading;
using threading::Value;
using threading::Field;

bool Stomp::LibraryInit()
	{
	activemq::library::ActiveMQCPP::initializeLibrary();

	return true;
	}

Stomp::Stomp(WriterFrontend* frontend) : WriterBackend(frontend)
	{

	set_separator.assign(
			(const char*) BifConst::LogAscii::set_separator->Bytes(),
			BifConst::LogAscii::set_separator->Len()
			);

	empty_field.assign(
			(const char*) BifConst::LogAscii::empty_field->Bytes(),
			BifConst::LogAscii::empty_field->Len()
			);

	unset_field.assign(
			(const char*) BifConst::LogAscii::unset_field->Bytes(),
			BifConst::LogAscii::unset_field->Len()
			);

	formatter::Ascii::SeparatorInfo sep_info(string(), set_separator, unset_field, empty_field);
	formatter = new formatter::Ascii(this, sep_info);
	}

Stomp::~Stomp()
	{
	delete formatter;
	}

bool Stomp::DoInit(const WriterInfo& info, int num_fields, const Field* const * fields)
	{
	std::map<const char*, const char*>::const_iterator it = info.config.find("topicName") ;
	if ( it == info.config.end() ) {
		Error(Fmt("topicName configuration option is not defined for stomp for %s", info.path));
		return false;
	}

	const char* topic = it->second;

#ifdef DEBUG
	Debug(DBG_LOGGING, "Trying to open stomp connection");
#endif

	try
		{
		auto_ptr<ConnectionFactory> connectionFactory (
				ConnectionFactory::createCMSConnectionFactory( info.path ) );

		connection = connectionFactory->createConnection();
		connection->start();

		session = connection->createSession( Session::AUTO_ACKNOWLEDGE );

		destination = session->createTopic( topic );

		producer = session->createProducer( destination );
		producer->setDeliveryMode( DeliveryMode::NON_PERSISTENT );

		}
	catch ( CMSException& e )
		{
		Error(Fmt("ActiveMQ Error: %s", e.getMessage().c_str()));
		return false;
		}
#ifdef DEBUG
	Debug(DBG_LOGGING, "Stomp connection should be open");
#endif

	return true;
	}

bool Stomp::DoFinish(double network_time)
	{
	// FIXME: destroy stuff here :)

	return true;
	}

bool Stomp::DoRotate(const char* rotated_path, double open, double close, bool terminating)
	{
	if ( ! FinishedRotation("/dev/null", Info().path, open, close, terminating))
		{
		Error(Fmt("error rotating %s", Info().path));
		return false;
		}

	return true;
	}

bool Stomp::AddParams(Value* val, MapMessage* m, int pos)
	{

	if ( ! val->present )
		{
			return false;
		}

	switch ( val->type ) {

	case TYPE_BOOL:
		m->setBoolean(Fields()[pos]->name, val->val.int_val ? 1 : 0);
		return true;

	case TYPE_INT:
		m->setInt(Fields()[pos]->name, val->val.int_val);
		return true;

	case TYPE_COUNT:
	case TYPE_COUNTER:
		m->setInt(Fields()[pos]->name, val->val.uint_val);
		return true;

	case TYPE_PORT:
		m->setInt(Fields()[pos]->name, val->val.port_val.port);
		return true;

	case TYPE_SUBNET:
		{
		string out = formatter->Render(val->val.subnet_val).c_str();
		m->setString(Fields()[pos]->name, out);
		return true;
		}

	case TYPE_ADDR:
		{
		string out = formatter->Render(val->val.addr_val).c_str();			
		m->setString(Fields()[pos]->name, out);
		return true;
		}

	case TYPE_TIME:
	case TYPE_INTERVAL:
	case TYPE_DOUBLE:
		m->setDouble(Fields()[pos]->name, val->val.double_val);
		return true;

	case TYPE_ENUM:
	case TYPE_STRING:
	case TYPE_FILE:
	case TYPE_FUNC:
		{
		if ( ! val->val.string_val.length || val->val.string_val.length == 0 ) 
			return false;

		string out(val->val.string_val.data, val->val.string_val.length);
		m->setString(Fields()[pos]->name, out);
		return true;
		}

	case TYPE_TABLE:
		{
		ODesc desc;
		desc.Clear();		
		desc.AddEscapeSequence(set_separator.c_str(), set_separator.size());

		for ( int j = 0; j < val->val.set_val.size; j++ )
			{
			if ( j > 0 )
				desc.AddRaw(set_separator.c_str(), set_separator.size());

			formatter->Describe(&desc, val->val.set_val.vals[j], "");
			}


		string out((const char*) desc.Bytes(), desc.Len());
		m->setString(Fields()[pos]->name, out);
		return true;
		}

	case TYPE_VECTOR:
		{
		ODesc desc;
		desc.Clear();		
		desc.AddEscapeSequence(set_separator.c_str(), set_separator.size());

		for ( int j = 0; j < val->val.vector_val.size; j++ )
			{
			if ( j > 0 )
				desc.AddRaw(set_separator.c_str(), set_separator.size());

			formatter->Describe(&desc, val->val.vector_val.vals[j], "");
			}

		string out((const char*) desc.Bytes(), desc.Len());
		m->setString(Fields()[pos]->name, out);
		return true;
		}

	default:
		Error(Fmt("unsupported field format %d", val->type ));
		return false;
	}
	}

bool Stomp::DoWrite(int num_fields, const Field* const * fields,
			     Value** vals)
	{

#ifdef DEBUG
	Debug(DBG_LOGGING, "DoWrite in Stomp");
#endif

	try
		{
		MapMessage* message = session->createMapMessage();

		bool atLeastOneField = false;

		for ( int i = 0; i < num_fields; i++ ) 
			atLeastOneField |= AddParams(vals[i], message, i); 

		if ( atLeastOneField) 
			producer->send(message);

		delete message;
		}
	catch (CMSException &e)
		{
		Error(Fmt("ActiveMQ Error: %s", e.getMessage().c_str()));
		return false;
		}

	return true;
	}
