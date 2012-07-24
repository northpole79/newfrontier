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
using threading::Value;
using threading::Field;

bool Stomp::LibraryInit()
	{
#ifdef DEBUG
	Debug(DBG_LOGGING, "Trying one-time activemq library initialization");
#endif

	activemq::library::ActiveMQCPP::initializeLibrary();

#ifdef DEBUG
	Debug(DBG_LOGGING, "Succeeded with one-time activemq library initialization");
#endif

	return true;
	}

Stomp::Stomp(WriterFrontend* frontend) : WriterBackend(frontend)
	{
	set_separator_len = BifConst::LogAscii::set_separator->Len();
	set_separator = new char[set_separator_len];
	memcpy(set_separator, BifConst::LogAscii::set_separator->Bytes(),
	       set_separator_len);
	
	}

Stomp::~Stomp()
	{
	delete [] set_separator;
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

// this one is mainly ripped from Ascii.cc - with some adaptions.
void Stomp::ValToAscii(ODesc* desc, Value* val)
	{
	if ( ! val->present )
		{
			assert(false);
		}

	switch ( val->type ) {

	case TYPE_BOOL:
		desc->Add(val->val.int_val ? "T" : "F");
		break;

	case TYPE_INT:
		desc->Add(val->val.int_val);
		break;

	case TYPE_COUNT:
	case TYPE_COUNTER:
		desc->Add(val->val.uint_val);
		break;

	case TYPE_PORT:
		desc->Add(val->val.port_val.port);
		break;

	case TYPE_SUBNET:
		desc->Add(Render(val->val.subnet_val));
		break;

	case TYPE_ADDR:
		desc->Add(Render(val->val.addr_val));
		break;

	case TYPE_DOUBLE:
		// Rendering via Add() truncates trailing 0s after the
		// decimal point. The difference with TIME/INTERVAL is mainly
		// to keep the log format consistent.
		desc->Add(val->val.double_val);
		break;

	case TYPE_INTERVAL:
	case TYPE_TIME:
		// Rendering via Render() keeps trailing 0s after the decimal
		// point. The difference with DOUBLEis mainly to keep the log
		// format consistent.
		desc->Add(Render(val->val.double_val));
		break;

	case TYPE_ENUM:
	case TYPE_STRING:
	case TYPE_FILE:
	case TYPE_FUNC:
		{
		int size = val->val.string_val.length;
		const char* data = val->val.string_val.data;

		if ( size )
			desc->AddN(data, size);

		break;
		}

	case TYPE_TABLE:
	case TYPE_VECTOR:
		assert(false);
		// this would mean that we have a table/vector inside a table/vector.
		// that is not possible and shoulr have been caught way earlier.

	default:
		// there may not be any types that we do not know here.
		assert(false);
	}

	}


void Stomp::AddParams(Value* val, MapMessage* m, int pos)
	{

	if ( ! val->present )
		{
			return;
		}

	switch ( val->type ) {

	case TYPE_BOOL:
		m->setBoolean(Fields()[pos]->name, val->val.int_val ? 1 : 0);
		return;

	case TYPE_INT:
		m->setInt(Fields()[pos]->name, val->val.int_val);
		return;

	case TYPE_COUNT:
	case TYPE_COUNTER:
		m->setInt(Fields()[pos]->name, val->val.uint_val);
		return;

	case TYPE_PORT:
		m->setInt(Fields()[pos]->name, val->val.port_val.port);
		return;

	case TYPE_SUBNET:
		{
		string out = Render(val->val.subnet_val).c_str();
		m->setString(Fields()[pos]->name, out);
		return;
		}

	case TYPE_ADDR:
		{
		string out = Render(val->val.addr_val).c_str();			
		m->setString(Fields()[pos]->name, out);
		return;
		}

	case TYPE_TIME:
	case TYPE_INTERVAL:
	case TYPE_DOUBLE:
		m->setDouble(Fields()[pos]->name, val->val.double_val);
		return;

	case TYPE_ENUM:
	case TYPE_STRING:
	case TYPE_FILE:
	case TYPE_FUNC:
		{
		if ( ! val->val.string_val.length || val->val.string_val.length == 0 ) 
			return;

		m->setString(Fields()[pos]->name, val->val.string_val.data);
		return;
		}

	case TYPE_TABLE:
		{
		ODesc desc;
		desc.Clear();		
		desc.AddEscapeSequence(set_separator, set_separator_len);

		for ( int j = 0; j < val->val.set_val.size; j++ )
			{
			if ( j > 0 )
				desc.AddRaw(set_separator, set_separator_len);

			ValToAscii(&desc, val->val.set_val.vals[j]);
			}


		string out((const char*) desc.Bytes(), desc.Len());
		m->setString(Fields()[pos]->name, out);
		return;
		}

	case TYPE_VECTOR:
		{
		ODesc desc;
		desc.Clear();		
		desc.AddEscapeSequence(set_separator, set_separator_len);

		for ( int j = 0; j < val->val.vector_val.size; j++ )
			{
			if ( j > 0 )
				desc.AddRaw(set_separator, set_separator_len);

			ValToAscii(&desc, val->val.vector_val.vals[j]);
			}

		string out((const char*) desc.Bytes(), desc.Len());
		m->setString(Fields()[pos]->name, out);
		return;
		}

	default:
		Error(Fmt("unsupported field format %d", val->type ));
		return;
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
		for ( int i = 0; i < num_fields; i++ ) 
			AddParams(vals[i], message, i); 

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
