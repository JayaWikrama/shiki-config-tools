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

int8_t sconf_setup(sconf_setup_parameter _parameters, uint16_t _value);

int8_t sconf_get_config(char* _file_name, char *_key, char *_return_value);
int8_t sconf_update_config(char* _file_name, char* _key, char* _value, ...);
int8_t sconf_update_keyword(char* _file_name, char* _old_key, char* _new_key);
int8_t sconf_remove_config(char* _file_name, char* _key);
int8_t sconf_remove_broken_config(char* _file_name);

int8_t sconf_start_create_new_config(char *_file_name, char *_key, char *_value, ...);
int8_t sconf_append_new_config(char *_file_name, char *_key, char *_value, ...);
int8_t sconf_end_new_config_file(char *_file_name);

int8_t sconf_insert_config(char *_file_name, char *_key, char *_value, ...);

int8_t sconf_set_additional_information(char *_file_name, char *_aditional_data);
int8_t sconf_append_additional_information(char *_file_name, char *_aditional_data);
int8_t sconf_get_additional_information(char *_file_name, char *_aditional_data, uint16_t _max_data_to_get);

int8_t sconf_disable_config(char *_file_name, char *_key);
int8_t sconf_enable_config(char *_file_name, char *_key);

int8_t sconf_check_config_by_line(char *_file_name, char *_line_value);
int8_t sconf_disable_config_by_line(char *_file_name, char *_line_value);
int8_t sconf_enable_config_by_line(char *_file_name, char *_line_value);
int8_t sconf_append_line_config(char *_file_name, char *_line_value);
#endif