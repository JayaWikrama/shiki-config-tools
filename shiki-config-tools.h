#ifndef __SHIKI_CONFIG_TOOLS__
#define __SHIKI_CONFIG_TOOLS__

#ifdef __cplusplus
    extern "C" {
#endif

#include <stdint.h>
#include "../shiki-linked-list/shiki-linked-list.h"

#define SCONF_DEBUG_ON 1
#define SCONF_DEBUG_OFF 0
#define SCONF_CHECK_WITH_SPACE 0
#define SCONF_CHECK_WITHOUT_SPACE 1


typedef enum {
    SCONF_SET_DEBUG_MODE = 0,
    SCONF_SET_MAX_BUFFER = 1,
    SCONF_SET_MAX_LINE_LENGTH = 2,
    SCONF_SET_OPEN_TRY_TIMES = 3,
    SCONF_SET_SEPARATOR = 4,
    SCONF_SET_DISABLE_FLAG = 5
} sconf_setup_parameter;

typedef enum {
    SCONF_READ_PURPOSE = 0,
    SCONF_UPDATE_PURPOSE = 1,
    SCONF_CREATE_PURPOSE = 2,
    SCONF_FORCE_WRITE = 3
} sconf_purpose_parameter;

typedef enum {
    SCONF_RULES_REFUSE_DUPLICATE_KEY = 0,
    SCONF_RULES_ALLOW_DUPLICATE_KEY = 1,
    SCONF_RULES_REFUSE_DUPLICATE_CONFIG = 1,
} sconf_rules;

typedef SHLink sconfList;

int8_t sconf_setup(sconf_setup_parameter _parameters, uint16_t _value);

int8_t sconf_get_checksum_file(const char *_file_name, char *_checksum);

int8_t sconf_copy_list(const char *_file_name, const char *_header_key, const char *_header_value, sconfList _source);
int8_t sconf_get_list(const char *_file_name, sconfList *_target);
int8_t sconf_open_config(const char *_file_name);
int8_t sconf_print_config(const char *_file_name);
void sconf_print_file_list();
void sconf_print_all();
int8_t sconf_close_config(const char *_file_name);
void sconf_close_all();

int8_t sconf_get_config_n(const char* _file_name, const char *_key, uint8_t _pos, char *_return_value);
int8_t sconf_get_config(const char* _file_name, const char *_key, char *_return_value);

char *sconf_get_config_as_string_n(const char* _file_name, const char *_key, uint8_t _pos);
char *sconf_get_config_as_string(const char* _file_name, const char *_key);
int sconf_get_config_as_int_n(const char* _file_name, const char *_key, uint8_t _pos);
int sconf_get_config_as_int(const char* _file_name, const char *_key);
long sconf_get_config_as_long_n(const char* _file_name, const char *_key, uint8_t _pos);
long sconf_get_config_as_long(const char* _file_name, const char *_key);
long long sconf_get_config_as_long_long_n(const char* _file_name, const char *_key, uint8_t _pos);
long long sconf_get_config_as_long_long(const char* _file_name, const char *_key);
float sconf_get_config_as_float_n(const char* _file_name, const char *_key, uint8_t _pos);
float sconf_get_config_as_float(const char* _file_name, const char *_key);

int8_t sconf_update_config_keyword_and_value(
 const char* _file_name,
 sconf_rules _rules,
 const char* _old_key,
 const char* _new_key,
 const char* _old_value,
 const char* _new_value
);
int8_t sconf_update_config_value(
 const char* _file_name,
 sconf_rules _rules,
 const char* _key,
 const char* _value, ...
);
int8_t sconf_update_config_keyword(
 const char* _file_name,
 sconf_rules _rules,
 const char* _old_key,
 const char* _new_key, ...
);
int8_t sconf_remove_config_by_keyword(const char* _file_name, const char* _key, ...);
int8_t sconf_remove_config_by_keyword_and_value(const char* _file_name, const char* _key, const char* _value);

int8_t sconf_insert_config(const char *_file_name, sconf_rules _rules, const char *_key, const char *_value, ...);

int8_t sconf_get_additional_information(const char *_file_name, char *_aditional_data, uint16_t _max_data_to_get);
int8_t sconf_update_additional_information(const char *_file_name, const char *_new_additional_data);
int8_t sconf_set_additional_information(const char *_file_name, const char *_additional_data);

int8_t sconf_disable_config_by_keyword(const char *_file_name, const char *_key);
int8_t sconf_enable_config_by_keyword(const char *_file_name, const char *_key);
int8_t sconf_disable_config_by_keyword_and_value(const char *_file_name, const char *_key, const char *_value);
int8_t sconf_enable_config_by_keyword_and_value(const char *_file_name, const char *_key, const char *_value);

int8_t sconf_generate_new_config_start(const char *_file_name);
int8_t sconf_generate_new_config_end(const char *_file_name);
int8_t sconf_force_write_config(const char *_file_name);
int8_t sconf_write_config_updates(const char *_file_name);
int8_t sconf_release_config_list(const char *_file_name);

#ifdef __cplusplus
    }
#endif

#endif