/*
ini.h - v1.2 - Simple ini-file reader for C/C++.
*/

#ifndef ini_h
#define ini_h

#define INI_GLOBAL_SECTION ( 0 )
#define INI_NOT_FOUND ( -1 )

typedef struct ini_t ini_t;

ini_t* ini_create( void* memctx );
ini_t* ini_load( char const* data, void* memctx );

int ini_save( ini_t const* ini, char* data, int size );
void ini_destroy( ini_t* ini );

int ini_section_count( ini_t const* ini );
char const* ini_section_name( ini_t const* ini, int section );

int ini_property_count( ini_t const* ini, int section );
char const* ini_property_name( ini_t const* ini, int section, int property );
char const* ini_property_value( ini_t const* ini, int section, int property );

int ini_find_section( ini_t const* ini, char const* name, int name_length );
int ini_find_property( ini_t const* ini, int section, char const* name, int name_length );

int ini_section_add( ini_t* ini, char const* name, int length );
void ini_property_add( ini_t* ini, int section, char const* name, int name_length, char const* value, int value_length );
void ini_section_remove( ini_t* ini, int section );
void ini_property_remove( ini_t* ini, int section, int property );

void ini_section_name_set( ini_t* ini, int section, char const* name, int length );
void ini_property_name_set( ini_t* ini, int section, int property, char const* name, int length );
void ini_property_value_set( ini_t* ini, int section, int property, char const* value, int length  );

#endif /* ini_h */
