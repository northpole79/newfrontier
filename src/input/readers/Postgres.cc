// See the file "COPYING" in the main distribution directory for copyright.

#include "Postgres.h"
#include "NetVar.h"

#include <fstream>
#include <sstream>

#include "../../threading/SerializationTypes.h"

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
	filters.empty();
	if ( conn != 0 )
		PQfinish(conn);	
}

bool Postgres::DoInit(string path, int arg_mode)
{
	started = false;
	mode = arg_mode;
	
	const char *conninfo;
	conninfo = "host = localhost dbname = test";
	conn = PQconnectdb(conninfo);

	if ( PQstatus(conn) != CONNECTION_OK ) {
		printf("Could not connect to pg: %s\n", PQerrorMessage(conn));
		InternalError(Fmt("Could not connect to pg: %s", PQerrorMessage(conn)));
		assert(false);
	}
	
	return true;
}

bool Postgres::DoStartReading() {
	if ( started == true ) {
		Error("Started twice");
		return false;
	}	

	started = true;
	switch ( mode ) {
		case MANUAL:
			DoUpdate();
			break;
		default:
			assert(false);
	}

	return true;
}

bool Postgres::DoAddFilter( int id, int arg_num_fields, const Field* const* fields ) {
	if ( HasFilter(id) ) {
		return false; // no, we don't want to add this a second time
	}

	Filter f;
	f.num_fields = arg_num_fields;
	f.fields = fields;

	filters[id] = f;

	return true;
}

bool Postgres::DoRemoveFilter ( int id ) {
	if (!HasFilter(id) ) {
		return false;
	}

	assert ( filters.erase(id) == 1 );

	return true;
}	


bool Postgres::HasFilter(int id) {
	map<int, Filter>::iterator it = filters.find(id);	
	if ( it == filters.end() ) {
		return false;
	}
	return true;
}


TransportProto Postgres::StringToProto(const string &proto) {
	if ( proto == "unknown" ) {
		return TRANSPORT_UNKNOWN;
	} else if ( proto == "tcp" ) {
		return TRANSPORT_TCP;
	} else if ( proto == "udp" ) {
		return TRANSPORT_UDP;
	} else if ( proto == "icmp" ) {
		return TRANSPORT_ICMP;
	}

	//assert(false);
	
	reporter->Error("Tried to parse invalid/unknown protocol: %s", proto.c_str());

	return TRANSPORT_UNKNOWN;
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
		string width = s.substr(pos+1);
		val->val.subnet_val.width = atoi(width.c_str());
		string addr = s.substr(0, pos);
		s = addr;
#ifdef BROv6
		if ( s.find(':') != s.npos ) {
			uint32* addr = new uint32[4];
			if ( inet_pton(AF_INET6, s.c_str(), addr) <= 0 ) {
				Error(Fmt("Bad IPv6 address: %s", s.c_str()));
				val->val.subnet_val.net[0] = val->val.subnet_val.net[1] = val->val.subnet_val.net[2] = val->val.subnet_val.net[3] = 0;
			}
			copy_addr(val->val.subnet_val.net, addr);
			delete addr;
		} else {
			val->val.subnet_val.net[0] = val->val.subnet_val.net[1] = val->val.subnet_val.net[2] = 0;
			if ( inet_aton(s.c_str(), &(val->val.subnet_val.net[3])) <= 0 ) {
				Error(Fmt("Bad addres: %s", s.c_str()));
		       		val->val.subnet_val.net[3] = 0;
			}
		}
#else
		if ( inet_aton(s.c_str(), (in_addr*) &(val->val.subnet_val.net)) <= 0 ) {
			Error(Fmt("Bad addres: %s", s.c_str()));
			val->val.subnet_val.net = 0;
		}
#endif
		break;

		}
	case TYPE_ADDR: {
		// NOTE: dottet_to_addr BREAKS THREAD SAFETY! it uses reporter.
		// Solve this some other time....
#ifdef BROv6
		if ( s.find(':') != s.npos ) {
			uint32* addr = dotted_to_addr6(s.c_str());
			copy_addr(val->val.addr_val, addr);
			delete addr;
		} else {
			val->val.addr_val[0] = val->val.addr_val[1] = val->val.addr_val[2] = 0;
		       	val->val.addr_val[3] = dotted_to_addr(s.c_str());
		}
#else
		uint32 t = dotted_to_addr(s.c_str());
		copy_addr(&t, val->val.addr_val);
#endif
		break;
		}

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

	int **mapping = new int *[filters.size()];
	int mappingPos = 0;
	for ( map<int, Filter>::iterator it = filters.begin(); it != filters.end(); it++ ) {

		const Field * const *fields = (*it).second.fields;
		int numfields = (*it).second.num_fields;
		mapping[mappingPos] = new int[numfields];

		for ( int i = 0; i < numfields; ++i ) {
			int pos = PQfnumber(res, fields[i]->name.c_str());
			if ( pos == -1 ) {
				printf("Field %s not found\n", fields[i]->name.c_str());
				assert(false);
			}

			mapping[mappingPos][i] = pos;
		}

		mappingPos++;
	}
			

	for (int i = 0; i < PQntuples(res); i++) {

		mappingPos = 0;
		for ( map<int, Filter>::iterator it = filters.begin(); it != filters.end(); it++ ) {
			int numfields = (*it).second.num_fields;
			Value** fields = new Value*[numfields];
			const Field * const*desc = (*it).second.fields;

			for ( int j = 0; j < numfields; ++j) {
				if ( PQgetisnull(res, i, mapping[mappingPos][j] ) == 1 ) {
					fields[j] = new Value(desc[j]->type, false);
				} else {
					char *str = PQgetvalue(res, i, mapping[mappingPos][j]);
					fields[j] = EntryToVal(str, desc[j]);
				}
			}

			SendEntry((*it).first, fields);

		}

	}



	for ( map<int, Filter>::iterator it = filters.begin(); it != filters.end(); it++ ) {
		EndCurrentSend((*it).first);
	}

	return true;
}

