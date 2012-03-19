// See the file "COPYING" in the main distribution directory for copyright.

#include "Postgres.h"
#include "NetVar.h"

#include <fstream>
#include <sstream>

#include "../../threading/SerialTypes.h"

#define MANUAL 0

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

using namespace input::reader;
using threading::Value;
using threading::Field;


Postgres::Postgres(ReaderFrontend *frontend) : ReaderBackend(frontend)
{
	
}

Postgres::~Postgres()
{
	DoFinish();

}

void Postgres::DoFinish()
{
	if ( conn != 0 )
		PQfinish(conn);	
}

bool Postgres::DoInit(string path, int arg_mode, int arg_num_fields, const threading::Field* const* arg_fields)
{
	started = false;
	mode = arg_mode;
	
	const char *conninfo;
	conninfo = "host = localhost dbname = test";
	conn = PQconnectdb(conninfo);
	
	num_fields = arg_num_fields;
	fields = arg_fields;

	if ( PQstatus(conn) != CONNECTION_OK ) {
		printf("Could not connect to pg: %s\n", PQerrorMessage(conn));
		InternalError(Fmt("Could not connect to pg: %s", PQerrorMessage(conn)));
		assert(false);
	}
	
	DoUpdate();

	return true;
}

Value* Postgres::EntryToVal(string s, const threading::Field *field) {

	Value* val = new Value(field->type, true);

	switch ( field->type ) {
	case TYPE_ENUM:
	case TYPE_STRING:
		val->val.string_val = new string(s);
		break;

	case TYPE_BOOL:
		if ( s == "t" ) {
			val->val.int_val = 1;
		} else if ( s == "f" ) {
			val->val.int_val = 0;
		} else {
			Error(Fmt("Invalid value for boolean: %s", s.c_str()));
			return false;
		}
		break;

	case TYPE_INT:
		val->val.int_val = atoi(s.c_str());
		break;

	case TYPE_DOUBLE:
	case TYPE_TIME:
	case TYPE_INTERVAL:
		val->val.double_val = atof(s.c_str());
		break;

	case TYPE_COUNT:
	case TYPE_COUNTER:
		val->val.uint_val = atoi(s.c_str());
		break;

	case TYPE_PORT:
		val->val.port_val.port = atoi(s.c_str());
		val->val.port_val.proto = TRANSPORT_UNKNOWN;
		break;

	case TYPE_SUBNET: {
		int pos = s.find("/");
		int width = atoi(s.substr(pos+1).c_str());
		string addr = s.substr(0, pos);

		val->val.subnet_val.prefix = StringToAddr(addr);
		val->val.subnet_val.length = width;		
		break;

		}
	case TYPE_ADDR: 
		val->val.addr_val = StringToAddr(s);			  
		break;

	case TYPE_TABLE:
	case TYPE_VECTOR:
		// First - common initialization
		// Then - initialization for table.
		// Then - initialization for vector.
		// Then - common stuff
		{
		// how many entries do we have...
		unsigned int length = 1;
		for ( unsigned int i = 0; i < s.size(); i++ )
			if ( s[i] == ',') length++;

		unsigned int pos = 0;
		
		/* if ( s.compare(empty_field) == 0 ) 
			length = 0;
			*/

		Value** lvals = new Value* [length];

		if ( field->type == TYPE_TABLE ) {
			val->val.set_val.vals = lvals;
			val->val.set_val.size = length;
		} else if ( field->type == TYPE_VECTOR ) {
			val->val.vector_val.vals = lvals;
			val->val.vector_val.size = length;
		} else {
			assert(false);
		}

		if ( length == 0 )
			break; //empty

		istringstream splitstream(s);
		while ( splitstream ) {
			string element;

			if ( !getline(splitstream, element, ',') )
				break;

			if ( pos >= length ) {
				Error(Fmt("Internal error while parsing set. pos %d >= length %d. Element: %s", pos, length, element.c_str()));
				break;
			}

			Field* newfield = new Field(*field);
			newfield->type = field->subtype;
			Value* newval = EntryToVal(element, newfield);
			delete(newfield);
			if ( newval == 0 ) {
				Error("Error while reading set");
				return 0;
			}
			lvals[pos] = newval;

			pos++;
	
		}


		if ( pos != length ) {
			Error("Internal error while parsing set: did not find all elements");
			return 0;
		}

		break;
		}


	default:
		Error(Fmt("unsupported field format %d for %s", field->type,
		field->name.c_str()));
		return 0;
	}	

	return val;

}

// read the entire file and send appropriate thingies back to InputMgr
bool Postgres::DoUpdate() {
	PGresult *res = PQexecParams(conn, "SELECT * from test", 0, NULL, NULL, NULL, NULL, 0);
	if (PQresultStatus(res) != PGRES_TUPLES_OK) {
		printf("Select failed: %s\n", PQerrorMessage(conn));
		PQclear(res);
		assert(false);
	}

	int *mapping = new int [num_fields];

	for ( unsigned int i = 0; i < num_fields; ++i ) {
		int pos = PQfnumber(res, fields[i]->name.c_str());
		if ( pos == -1 ) {
			printf("Field %s not found\n", fields[i]->name.c_str());
			assert(false);
		}

		mapping[i] = pos;
	}


	for ( int i = 0; i < PQntuples(res); i++) {

		Value** ofields = new Value*[num_fields];

		for ( unsigned int j = 0; j < num_fields; ++j) {
			if ( PQgetisnull(res, i, mapping[j] ) == 1 ) {
				ofields[j] = new Value(fields[j]->type, false);
			} else {
				char *str = PQgetvalue(res, i, mapping[j]);
				ofields[j] = EntryToVal(str, fields[j]);
			}
		}

		SendEntry(ofields);
	}



	EndCurrentSend();

	delete (mapping);

	return true;
}

