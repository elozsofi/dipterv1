#ifndef __AITIA_IO_SQLDB
#define __AITIA_IO_SQLDB

#include <string>
#include <map>
#include "mariadb/mysql.h"
#include "../logger-common.h"

#define SQL_STRING_MAXLENGTH	256

typedef enum SQL_Types
{
	SQL_INT = 0,
	SQL_STRLIM = 1,
	SQL_DOUBLE = 2,
	SQL_LONG = 3,
	SQL_STRING = 4,
	SQL_END = -1
} SQL_Types;

typedef struct SQL_data
{
	SQL_Types type;
	char *data;
	unsigned long *length;
} SQL_data;

typedef struct SQL_tr
{
#define SQL_MAX_BINDS 16
	MYSQL_BIND binds_para[SQL_MAX_BINDS];
	MYSQL_BIND binds_res[SQL_MAX_BINDS];
	unsigned int act_para;
	unsigned int act_res;
	MYSQL_STMT *stmt;

	int bind_params(const SQL_data *pdata);
	int bind_results(const SQL_data *pdata);

	bool execute();
	bool fetch();
	bool clean();
	void end();

} SQL_tr;

typedef std::map<std::string, SQL_tr> SQL_trmap;

class SQLDB 
{
public:
	SQLDB() { plog = NULL; db = NULL; }
	void setlogger(SGA_Logger *plogger) { plog = plogger; }

	bool open(const char *address, const unsigned short port, const char *dbname, const char *dbuser, const char *dbpass, const char *dbopts);
	bool close();

	bool add_statement(const char* name, const char* statement);
	SQL_tr& operator[](const char* name);
//
	int query(const char *pquery);
	unsigned long *getnextrow();
	void clean();

	unsigned int getfields() { return num_fields; }
	void freerows() { if (presult) { mysql_free_result(presult); presult = NULL;}}
	char *getvalue(unsigned int field) { if (field < num_fields) return row[field]; else return NULL; }

private:
	MYSQL *db;
	SQL_trmap trs;
//
	SGA_Logger *plog;
	MYSQL_RES *presult;
	MYSQL_ROW row;
	unsigned int num_fields;
};

#endif // __AITIA_IO_SQLDB
