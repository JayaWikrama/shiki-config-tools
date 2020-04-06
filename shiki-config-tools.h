#ifndef __SHIKI_CONFIG_TOOLS__
#define __SHIKI_CONFIG_TOOLS__

#include <stdint.h>

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
    SCONF_CREATE_PURPOSE = 2
} sconf_purpose_parameter;

typedef enum {
    SCONF_RULES_REFUSE_DUPLICATE_KEY = 0,
    SCONF_RULES_ALLOW_DUPLICATE_KEY = 1,
    SCONF_RULES_REFUSE_DUPLICATE_CONFIG = 1,
} sconf_rules;

int8_t sconf_setup(sconf_setup_parameter _parameters, uint16_t _value);

int8_t sconf_get_checksum_file(char *_file_name, char *_checksum);

int8_t sconf_open_config(char *_file_name);
int8_t sconf_print_config(char *_file_name);
int8_t sconf_close_config(char *_file_name);
int8_t sconf_get_config(char* _file_name, char *_key, char *_return_value);
int8_t sconf_get_config_n(char* _file_name, char *_key, uint8_t _pos, char *_return_value);
int8_t sconf_update_config_keyword_and_value(char* _file_name, sconf_rules _rules, char* _old_key, char* _new_key, char* _old_value, char* _new_value);
int8_t sconf_update_config_value(char* _file_name, sconf_rules _rules, char* _key, char* _value, ...);
int8_t sconf_update_config_keyword(char* _file_name, sconf_rules _rules, char* _old_key, char* _new_key, ...);
int8_t sconf_remove_config_by_keyword(char* _file_name, char* _key, ...);
int8_t sconf_remove_config_by_keyword_and_value(char* _file_name, char* _key, char* _value);

int8_t sconf_start_create_new_config(char *_file_name, char *_key, char *_value, ...);
int8_t sconf_append_new_config(char *_file_name, char *_key, char *_value, ...);
int8_t sconf_end_new_config_file(char *_file_name);

int8_t sconf_insert_config(char *_file_name, sconf_rules _rules, char *_key, char *_value, ...);

int8_t sconf_get_additional_information(char *_file_name, char *_aditional_data, uint16_t _max_data_to_get);
int8_t sconf_update_additional_information(char *_file_name, char *_new_additional_data);
int8_t sconf_set_additional_information(char *_file_name, char *_additional_data);

int8_t sconf_disable_config_by_keyword(char *_file_name, char *_key);
int8_t sconf_enable_config_by_keyword(char *_file_name, char *_key);
int8_t sconf_disable_config_by_keyword_and_value(char *_file_name, char *_key, char *_value);
int8_t sconf_enable_config_by_keyword_and_value(char *_file_name, char *_key, char *_value);

int8_t sconf_generate_new_config_start(char *_file_name);
int8_t sconf_generate_new_config_end(char *_file_name);
int8_t sconf_write_config_updates(char *_file_name);
#endif