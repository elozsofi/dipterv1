#include "sga_sqldb.h"
#include <string.h>

///
using namespace std;

bool SQLDB::open(const char *address, const unsigned short port, const char *dbname, const char *dbuser, const char *dbpass, const char *dbopts)
{
	db = mysql_init(NULL);
	if (!db)
		return false;
	// auto-reconnect
	bool reconnect = true;
    mysql_optionsv(db, MYSQL_OPT_RECONNECT, &reconnect);
    // connection timeout
	unsigned int timeout= 5;
	mysql_optionsv(db, MYSQL_OPT_CONNECT_TIMEOUT, (void *)&timeout);        
	mysql_optionsv(db, MYSQL_OPT_READ_TIMEOUT , (void *)&timeout);       
    mysql_optionsv(db, MYSQL_OPT_WRITE_TIMEOUT , (void *)&timeout);          
    // Options defined for client (like secure connection, etc...)
    if (dbopts)
	mysql_optionsv(db, MYSQL_READ_DEFAULT_FILE, (void *)dbopts);

    if (!mysql_real_connect(db, address, dbuser, dbpass, dbname, port, NULL, 0))
    {
    	plog->WRITE_LOG(LOG_ERR, "SQL open error: %s\n", mysql_error(db));
    	return false;
    }
    return true;
}

bool SQLDB::close()
{
	if (!db) return false;
	for (auto & it : trs)
	{
		it.second.end();
	}
	trs.clear();

	mysql_close(db);
	db = NULL;
	return true;
}

// from DDOS projects
int SQLDB::query(const char *pquery)
{

	if (!db)
		return -1;

	if (mysql_query(db, pquery))
	{
	    plog->WRITE_LOG(LOG_ERR, "SQL Error: %s\n", mysql_error(db));
//	    close();
	    return -1;
	}

	presult = mysql_store_result(db);  
	if (!presult)
	{
//		if (!mysql_field_count(db)) return 0;
		if (mysql_errno(db) == 0) return 0; // no error
		plog->WRITE_LOG(LOG_ERR, "SQL Error: %s\n", mysql_error(db)); 
//		close();
		return -1;
	}
	num_fields = mysql_num_fields(presult);
	return mysql_num_rows(presult); // returns the nr of rows in the result
}

unsigned long *SQLDB::getnextrow()
{
	row = mysql_fetch_row(presult);
	if (!row) 
	{
		freerows();
		return NULL;
	}
	return mysql_fetch_lengths(presult); // returns the length array of results
}

bool SQLDB::add_statement(const char* name, const char* statement)
{
	SQL_tr atr;

	if (!db) return false;
	atr.stmt = mysql_stmt_init(db);
	if (!atr.stmt) return false;

	if (mysql_stmt_prepare(atr.stmt, statement, strlen(statement)))
		return false;

	trs.insert(std::make_pair(name, atr));
	return true;
}

SQL_tr& SQLDB::operator[](const char* name) 
{
	return trs[name];
}

//

int SQL_tr::bind_params(const SQL_data *pbinds)
{

act_para = 0;
while (pbinds->type != SQL_END && act_para < SQL_MAX_BINDS)
{
	memset(&binds_para[act_para], 0, sizeof(MYSQL_BIND));
	switch (pbinds->type)
	{
	case SQL_INT:
		binds_para[act_para].buffer_type = MYSQL_TYPE_LONG;
		break;
	case SQL_STRLIM:
		binds_para[act_para].buffer_type = MYSQL_TYPE_STRING;
		binds_para[act_para].buffer_length = SQL_STRING_MAXLENGTH;
		binds_para[act_para].length = pbinds->length;
		break;
	case SQL_DOUBLE:
		binds_para[act_para].buffer_type = MYSQL_TYPE_DOUBLE;
		break;
	case SQL_LONG:
		binds_para[act_para].buffer_type = MYSQL_TYPE_LONGLONG;
		break;
	default:
		break;
	}
	binds_para[act_para].buffer = pbinds->data;
	act_para++;
	pbinds++;
}
if (mysql_stmt_bind_param(stmt, binds_para)) return 0;

return act_para;
}

int SQL_tr::bind_results(const SQL_data *pbinds)
{

act_res = 0;
while (pbinds->type != SQL_END && act_res < SQL_MAX_BINDS)
{
	memset(&binds_res[act_res], 0, sizeof(MYSQL_BIND));
	switch (pbinds->type)
	{
	case SQL_INT:
		binds_res[act_res].buffer_type = MYSQL_TYPE_LONG;
		break;
	case SQL_STRLIM:
		binds_res[act_res].buffer_type = MYSQL_TYPE_STRING;
		binds_res[act_res].buffer_length = SQL_STRING_MAXLENGTH;
		break;
	case SQL_DOUBLE:
		binds_res[act_res].buffer_type = MYSQL_TYPE_DOUBLE;
		break;
	case SQL_LONG:
		binds_res[act_res].buffer_type = MYSQL_TYPE_LONGLONG;
		break;
	default:
		break;
	}
	binds_res[act_res].buffer = pbinds->data;
	act_res++;
	pbinds++;
}
if (mysql_stmt_bind_result(stmt, binds_res)) return 0;

return act_res;
}

bool SQL_tr::execute()
{
	 if (mysql_stmt_execute(stmt)) return false;
	 if (mysql_stmt_store_result(stmt)) 
	 {
	 	clean();
	 	return false;
	 }
	 return true;
}

bool SQL_tr::fetch()
{
	int ret = mysql_stmt_fetch(stmt);
	return (ret==0)?true:false;
}

bool SQL_tr::clean()
{
	return (mysql_stmt_free_result(stmt)==0)?true:false;
}

void SQL_tr::end()
{
	mysql_stmt_close(stmt);
	stmt = NULL;
}

