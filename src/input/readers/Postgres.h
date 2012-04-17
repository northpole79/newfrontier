// See the file "COPYING" in the main distribution directory for copyright.

#ifndef INPUT_READERS_POSTGRES_H
#define INPUT_READERS_POSTGRES_H

#include "config.h"

#ifdef USE_POSTGRES

#include <iostream>
#include <vector>

#include "../ReaderBackend.h"
#include "libpq-fe.h"

namespace input { namespace reader {

class Postgres : public ReaderBackend {
public:
    Postgres(ReaderFrontend* frontend);
    ~Postgres();
    
    static ReaderBackend* Instantiate(ReaderFrontend* frontend) { return new Postgres(frontend); }
    
protected:
	
	virtual bool DoInit(string path, int mode, int arg_num_fields, const threading::Field* const* fields); 

	virtual void DoFinish();

	virtual bool DoUpdate();

private:

	unsigned int num_fields;

	const threading::Field* const * fields; // raw mapping		

	threading::Value* EntryToVal(string s, const threading::Field *type);

	int mode;

	bool started;
	string query;

	PGconn *conn;	

};


}
}

#endif /* USE_POSTGRES */

#endif /* INPUT_READERS_POSTGRES_H */
