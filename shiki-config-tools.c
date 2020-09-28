/*
    lib info    : SHIKI_LIB_GROUP - CONFIG TOOLS
    ver         : 3.01.20.09.28
    author      : Jaya Wikrama, S.T.
    e-mail      : jayawikrama89@gmail.com
    Copyright (c) 2020 HANA,. Jaya Wikrama
*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>

#include "shiki-config-tools.h"

#define SCONF_VERSION "3.01.20.09.28"

#define sconf_get_var_name(_var) #_var

typedef enum {
  SCONF_DEBUG_INFO = 0x00,
  SCONF_DEBUG_VERSION = 0x01,
  SCONF_DEBUG_WARNING = 0x02,
  SCONF_DEBUG_ERROR = 0x03,
  SCONF_DEBUG_CRITICAL = 0x04
} sconf_debug_type;

int8_t sconf_debug_mode_status = 1;

uint16_t SCONF_MAX_BUFF = 256;
uint8_t SCONF_OPEN_TRY_TIMES = 1;
char SCONF_SEPARATOR = '=';
char SCONF_DISABLE_FLAG = '#';

uint16_t SCONF_MAX_LINE_LENGTH = 200;
int8_t SCONF_SKIP_SPACE_FROM_LINE = SCONF_CHECK_WITH_SPACE;

SHLink sconf_list = NULL;

static void sconf_debug(const char *_function_name, sconf_debug_type _debug_type, const char *_debug_msg, ...);
static int8_t sconf_update_config(
 const char* _file_name,
 sconf_rules _rules,
 const char* _old_key,
 const char* _new_key,
 const char* _old_value,
 const char* _new_value
);
static int8_t sconf_remove_config(
 const char* _file_name,
 const char* _key,
 const char* _value
);
static int8_t sconf_write_config(
 const char *_file_name,
 const char *_file_alias,
 char *_valid_checksum,
 sconf_purpose_parameter _param
);

static void sconf_debug(const char *_function_name, sconf_debug_type _debug_type, const char *_debug_msg, ...){
	if (sconf_debug_mode_status == 1 || _debug_type != SCONF_DEBUG_INFO){
        struct tm *d_tm = NULL;
        struct timeval tm_debug;
        uint16_t msec = 0;
		
	    gettimeofday(&tm_debug, NULL);
	    d_tm = localtime(&tm_debug.tv_sec);
        msec = tm_debug.tv_usec/1000;

        #ifdef __linux__
            if (_debug_type == SCONF_DEBUG_INFO)
                printf("%02d-%02d-%04d %02d:%02d:%02d.%03d\033[0;34m STCP\033[1;32m INFO\033[0m %s: ",
                 d_tm->tm_mday, d_tm->tm_mon+1, d_tm->tm_year+1900, d_tm->tm_hour, d_tm->tm_min, d_tm->tm_sec,
                 msec, _function_name
                );
            else if (_debug_type == SCONF_DEBUG_VERSION)
                printf("%02d-%02d-%04d %02d:%02d:%02d.%03d\033[0;34m STCP\033[1;32m VERSION\033[0m %s: ",
                 d_tm->tm_mday, d_tm->tm_mon+1, d_tm->tm_year+1900, d_tm->tm_hour, d_tm->tm_min, d_tm->tm_sec,
                 msec, _function_name
                );
    	    else if (_debug_type == SCONF_DEBUG_WARNING)
                printf("%02d-%02d-%04d %02d:%02d:%02d.%03d\033[0;34m STCP\033[1;33m WARNING\033[0m %s: ",
                 d_tm->tm_mday, d_tm->tm_mon+1, d_tm->tm_year+1900, d_tm->tm_hour, d_tm->tm_min, d_tm->tm_sec,
                 msec, _function_name
                );
    	    else if (_debug_type == SCONF_DEBUG_ERROR)
                printf("%02d-%02d-%04d %02d:%02d:%02d.%03d\033[0;34m STCP\033[1;31m ERROR\033[0m %s: ",
                 d_tm->tm_mday, d_tm->tm_mon+1, d_tm->tm_year+1900, d_tm->tm_hour, d_tm->tm_min, d_tm->tm_sec,
                 msec, _function_name
                );
            else if (_debug_type == SCONF_DEBUG_CRITICAL)
                printf("%02d-%02d-%04d %02d:%02d:%02d.%03d\033[0;34m STCP\033[1;31m CRITICAL\033[0m %s: ",
                 d_tm->tm_mday, d_tm->tm_mon+1, d_tm->tm_year+1900, d_tm->tm_hour, d_tm->tm_min, d_tm->tm_sec,
                 msec, _function_name
                );
	    #else
            printf("%02d-%02d-%04d %02d:%02d:%02d.%03d [%02x]: %s: ",
             d_tm->tm_mday, d_tm->tm_mon+1, d_tm->tm_year+1900, d_tm->tm_hour, d_tm->tm_min, d_tm->tm_sec,
             msec, _debug_type, _function_name
            );
        #endif

        va_list aptr;
        va_start(aptr, _debug_msg);
	    vfprintf(stdout, _debug_msg, aptr);
	    va_end(aptr);
    }
}

static SHLink sconf_get_config_file_in_list(const char *_file_name){
    SHLinkCustomData data_result;
    if (shilink_search_data_by_position(
     sconf_list,
     (void *) _file_name,
     (uint16_t) (strlen(_file_name) % UINT16_MAX),
     0,
     &data_result
    )){
        return NULL;
    }
    return data_result.sl_value;
}

static int8_t sconf_add_file(const char *_file_name, const SHLink _conf_list){
    SHLinkCustomData data_add;
    if (shilink_fill_custom_data(
     &data_add,
     (void *) _file_name,
     (uint16_t) (strlen(_file_name) % UINT16_MAX),
     NULL,
     0,
     SL_POINTER
    )){
        sconf_debug(__func__, SCONF_DEBUG_ERROR, "failed to generate list for file (%s)\n", _file_name);
        return 0x01;
    }
    data_add.sl_value = (void *) _conf_list;
    if (shilink_append(&sconf_list, data_add)){
        sconf_debug(__func__, SCONF_DEBUG_ERROR, "failed to add list for file (%s)\n", _file_name);
        shilink_free_custom_data(&data_add);
        return 0x02;
    }
    return 0x00;
}

static void sconf_append_data_checksum(unsigned char *_checksum_data, const unsigned char *_data, uint16_t _sizeof_data){
    unsigned long cs = 0;
    unsigned long max_cs = 0;
    memcpy(&cs, _checksum_data, sizeof(cs));
    memset(&max_cs, 0xFF, sizeof(max_cs));

    uint16_t idx_char = 0;

    if (cs == 0){
        cs = 1;
    }

    for (idx_char=0; idx_char<_sizeof_data; idx_char++){
        while ((cs * _data[idx_char]) >= max_cs/512){
            cs = cs / 2;
        }
        cs = cs * _data[idx_char];
    }

    memcpy(_checksum_data, &cs, sizeof(cs));
}

static void sconf_output_checksum_string(char *_checksum_str, const unsigned char *_checksum_data){
    uint8_t idx_data = 0x00;
    char checksum[(2*sizeof(long))+1];
    char bytes[3];
    memset(checksum, 0x00, sizeof(checksum));

    for (idx_data=0x00; idx_data<sizeof(long); idx_data++){
        memset(bytes, 0x00, sizeof(bytes));
        sprintf(bytes, "%02X", _checksum_data[idx_data]);
        strcat(checksum, bytes);        
    }

    strcpy(_checksum_str, checksum);
}

int8_t sconf_get_checksum_file(const char *_file_name, char *_checksum){
    FILE *conf_file = NULL;
    uint8_t try_times = SCONF_OPEN_TRY_TIMES;
    unsigned char checksum_data[sizeof(long)];
    char checksum_str[(2*sizeof(long))+1];
    memset(checksum_data, 0x00, sizeof(checksum_data));
    memset(checksum_str, 0x00, sizeof(checksum_str));

    do{
    	conf_file = fopen(_file_name, "r");
        try_times--;
    } while (conf_file == NULL && try_times > 0);

    if (conf_file == NULL){
        sconf_debug(__func__, SCONF_DEBUG_ERROR, "failed to open config file\n");
        return -1;
    }

	char character = 0x00;
    char data[2];
	
    fseek(conf_file, 0L, SEEK_SET);
	while((character = fgetc(conf_file)) != EOF){
		if (character > 127 || character < 9) break;
        data[0] = character;
        data[1] = 0x00;
        sconf_append_data_checksum(checksum_data, (unsigned char*) data, 1);
	}
    
    fclose(conf_file);
    conf_file = NULL;

    sconf_output_checksum_string(checksum_str, checksum_data);

    strcpy(_checksum, checksum_str);
    return 0;
}

int8_t sconf_setup(sconf_setup_parameter _parameters, uint16_t _value){
    if (_parameters == SCONF_SET_DEBUG_MODE){
        if (_value == SCONF_DEBUG_OFF || _value == SCONF_DEBUG_ON){
            sconf_debug_mode_status = _value;
        }
        else {
            sconf_debug(__func__, SCONF_DEBUG_WARNING, "invalid value\n");
        }
    }
    else if (_parameters == SCONF_SET_MAX_BUFFER){
        SCONF_MAX_BUFF = _value;
    }
    else if (_parameters == SCONF_SET_MAX_LINE_LENGTH){
        SCONF_MAX_LINE_LENGTH = _value;
    }
    else if (_parameters == SCONF_SET_OPEN_TRY_TIMES){
        SCONF_OPEN_TRY_TIMES = _value;
    }
    else if (_parameters == SCONF_SET_SEPARATOR){
        SCONF_SEPARATOR = (char) _value;
    }
    else if (_parameters == SCONF_SET_DISABLE_FLAG){
        SCONF_DISABLE_FLAG = (char) _value;
    }
    else {
        sconf_debug(__func__, SCONF_DEBUG_WARNING, "invalid parameters\n");
    }
    return 0;
}

int8_t sconf_copy_list(const char *_file_name, const char *_header_key, const char *_header_value, sconfList _source){
    SHLink sconf_tmp = NULL;
    sconf_tmp = sconf_get_config_file_in_list(_file_name);
    if (sconf_tmp != NULL){
        sconf_debug(__func__, SCONF_DEBUG_WARNING, "config for \"%s\" already exist.. process aborted!\n", _file_name);
        return -3;
    }

    SHLinkCustomData conf_data;
    shilink_fill_custom_data(
     &conf_data,
     (void *) "SCONF_FILE_NAME",
     15,
     (void *) _file_name,
     (uint16_t) strlen(_file_name),
     SL_TEXT
    );
    shilink_append(&sconf_tmp, conf_data);
    if (_header_key != NULL && _header_value != NULL){
        shilink_fill_custom_data(&conf_data,
         (void *) _header_key,
         (uint16_t) strlen(_header_key),
         (void *) _header_value,
         (uint16_t) strlen(_header_value),
         SL_TEXT
        );
        shilink_append(&sconf_tmp, conf_data);
        sconf_tmp->sh_next->sh_next = _source;
    }
    else {
        sconf_tmp->sh_next = _source;
    }
    if (sconf_add_file(_file_name, sconf_tmp)){
        shilink_free(&sconf_tmp);
        sconf_tmp = NULL;
        sconf_debug(__func__, SCONF_DEBUG_ERROR, "failed to copy list for %s\n", _file_name);
        return -4;
    }
    return 0;
}

int8_t sconf_get_list(const char *_file_name, sconfList *_target){
    SHLink sconf_tmp = NULL;
    sconf_tmp = sconf_get_config_file_in_list(_file_name);
    if (sconf_tmp == NULL){
        sconf_debug(__func__, SCONF_DEBUG_WARNING, "configuration for (%s) is not exist or not opened yet.. process aborted!\n", _file_name);
        return -3;
    }

    *_target = sconf_tmp;
    return 0;
}

int8_t sconf_open_config(const char *_file_name){
    SHLink sconf_tmp = NULL;
    sconf_tmp = sconf_get_config_file_in_list(_file_name);
    if (sconf_tmp != NULL){
        sconf_debug(__func__, SCONF_DEBUG_WARNING, "you have opened the configuration (%s).. process aborted!\n", _file_name);
        return -3;
    }

    FILE *conf_file = NULL;
    uint8_t try_times = SCONF_OPEN_TRY_TIMES;

    do{
    	conf_file = fopen(_file_name, "r");
        try_times--;
    } while (conf_file == NULL && try_times > 0);

    if (conf_file == NULL){
        sconf_debug(__func__, SCONF_DEBUG_ERROR, "failed to open config file (%s)\n", _file_name);
        return -1;
    }

	char *buff_init = NULL;
    buff_init = (char *) malloc(8*sizeof(char));
    if (buff_init == NULL){
        sconf_debug(__func__, SCONF_DEBUG_ERROR, "failed to allocate buff_init memory\n");
        fclose(conf_file);
        return -2;
    }

    char *buff_conf;
    buff_conf = (char *) malloc(8*sizeof(char));
    if (buff_conf == NULL){
        sconf_debug(__func__, SCONF_DEBUG_ERROR, "failed to allocate buff_conf memory\n");
        free(buff_init);
        buff_init = NULL;
        fclose(conf_file);
        return -2;
    }

	char character = 0x00;
	uint16_t idx_char = 0;
	int8_t idx_conf = 0x00;
    int8_t additional_info_flag = 0x00;
    uint16_t conf_size = 8;

    SHLinkCustomData conf_data;
    shilink_fill_custom_data(
     &conf_data,
     (void *) "SCONF_FILE_NAME",
     15,
     (void *) _file_name,
     (uint16_t) strlen(_file_name),
     SL_TEXT
    );
    shilink_append(&sconf_tmp, conf_data);

	memset(buff_init, 0x00, conf_size*sizeof(char));
	memset(buff_conf, 0x00, conf_size*sizeof(char));

    fseek(conf_file, 0L, SEEK_SET);
	while((character = fgetc(conf_file)) != EOF){
		if (character > 127 || character < 9) break;
        if (additional_info_flag == 0){
		    if (character == '\n'){
                if (strcmp(buff_init, "[END]") == 0){
                    additional_info_flag = 1;
                }
		    	shilink_fill_custom_data(
                 &conf_data,
                 (void *) buff_init,
                 (uint16_t) strlen(buff_init),
                 (void *) buff_conf,
                 (uint16_t) strlen(buff_conf),
                 SL_TEXT);
                shilink_append(&sconf_tmp, conf_data);

		    	memset(buff_init, 0x00, (strlen(buff_init) + 1)*sizeof(char));
		    	memset(buff_conf, 0x00, (strlen(buff_conf) + 1)*sizeof(char));
                conf_size = 8;
		    	idx_conf=idx_char=0;
                buff_init = (char *) realloc(buff_init, conf_size*sizeof(char));
                buff_conf = (char *) realloc(buff_conf, conf_size*sizeof(char));
		    }
		    else if(idx_conf==0 && character != SCONF_SEPARATOR){
                if(conf_size < (idx_char + 2)){
                    conf_size = conf_size + 8;
                    buff_init = (char *) realloc(buff_init, conf_size*sizeof(char));
                }
                buff_init[idx_char] = character;
                buff_init[idx_char + 1] = 0x00;
		    	idx_char++;
		    }
		    else if(idx_conf==1){
		    	if(conf_size < (idx_char + 2)){
                    conf_size = conf_size + 8;
                    buff_conf = (char *) realloc(buff_conf, conf_size*sizeof(char));
                }
                buff_conf[idx_char] = character;
                buff_conf[idx_char + 1] = 0x00;
                idx_char++;
		    }
		    else if(character == SCONF_SEPARATOR){
		    	idx_char = 0;
		    	idx_conf = 1;
                conf_size = 8;
		    }
        } else {
            if(conf_size < (idx_char + 2)){
                conf_size = conf_size + 8;
                buff_init = (char *) realloc(buff_init, conf_size*sizeof(char));
            }
            buff_init[idx_char] = character;
            buff_init[idx_char + 1] = 0x00;
		    idx_char++;
        }
	}
    
    if (additional_info_flag == 0x01 && strlen(buff_init) > 0){
        shilink_fill_custom_data(
         &conf_data,
         (void *) "add_info",
         8,
         (void *) buff_init,
         (uint16_t) strlen(buff_init),
         SL_TEXT
        );
        shilink_append(&sconf_tmp, conf_data);
    }
    
    free(buff_init);
    free(buff_conf);
    buff_init = NULL;
    buff_conf = NULL;
	fclose(conf_file);
    conf_file = NULL;

    if (sconf_add_file(_file_name, sconf_tmp)){
        shilink_free(&sconf_tmp);
        sconf_tmp = NULL;
        sconf_debug(__func__, SCONF_DEBUG_ERROR, "failed to copy list for %s\n", _file_name);
        return -4;
    }
    return 0;
}

int8_t sconf_print_config(const char *_file_name){
    SHLink sconf_tmp = NULL;
    sconf_tmp = sconf_get_config_file_in_list(_file_name);
    if (sconf_tmp == NULL){
        sconf_debug(__func__, SCONF_DEBUG_WARNING, "configuration for (%s) is not exist or not opened yet.. process aborted!\n", _file_name);
        return -3;
    }
    shilink_print(sconf_tmp);
    return 0;
}

void sconf_print_file_list(){
    SHLink sconf_print = sconf_list;
    SHLink sconf_tmp = NULL;
    if (sconf_print == NULL){
        sconf_debug(__func__, SCONF_DEBUG_INFO, "null configuration file in list\n");
    }
    while (sconf_print != NULL){
        sconf_tmp = sconf_print;
        sconf_print = sconf_print->sh_next;
        sconf_debug(__func__, SCONF_DEBUG_INFO, "config available: %s\n", (char *) sconf_tmp->sl_data.sl_key);
    }
}

void sconf_print_all(){
    SHLink sconf_print = sconf_list;
    SHLink sconf_tmp = NULL;
    if (sconf_print == NULL){
        sconf_debug(__func__, SCONF_DEBUG_INFO, "null configuration file in list\n");
    }
    while (sconf_print != NULL){
        sconf_tmp = sconf_print;
        sconf_print = sconf_print->sh_next;
        sconf_debug(__func__, SCONF_DEBUG_INFO, "config available: %s\n", (char *) sconf_tmp->sl_data.sl_key);
        sconf_print_config((const char *) sconf_tmp->sl_data.sl_key);
    }
}

int8_t sconf_close_config(const char *_file_name){
    SHLink sconf_tmp = NULL;
    sconf_tmp = sconf_get_config_file_in_list(_file_name);
    if (sconf_tmp == NULL){
        sconf_debug(__func__, SCONF_DEBUG_WARNING, "configuration for (%s) is not exist or not opened yet.. process aborted!\n", _file_name);
        return -3;
    }
    SHLinkCustomData data_deleted;
    shilink_free(&(sconf_tmp->sh_next));
    shilink_fill_custom_data(
     &data_deleted,
     (void *) _file_name,
     (uint16_t) (strlen(_file_name) % UINT16_MAX),
     NULL,
     0,
     SL_POINTER
    );
    if (shilink_delete(&sconf_list, data_deleted)){
        sconf_debug(__func__, SCONF_DEBUG_WARNING, "configuration for (%s) has been free, but failed to deleted from list.\n", _file_name);
        return -4;
    }
    return 0;
}

void sconf_close_all(){
    SHLink sconf_tmp = NULL;
    while (sconf_list != NULL){
        sconf_tmp = sconf_list;
        sconf_list = sconf_list->sh_next;
        sconf_debug(__func__, SCONF_DEBUG_INFO, "close config: %s\n", (char *) sconf_tmp->sl_data.sl_key);
        shilink_free((SHLink *) &(sconf_tmp->sl_data.sl_value));
        free(sconf_tmp->sl_data.sl_key);
        sconf_tmp->sl_data.sl_key = NULL;
        sconf_tmp->sl_data.sl_value = NULL;
        free(sconf_tmp);
        sconf_tmp = NULL;
    }
    sconf_list = NULL;
}

int8_t sconf_get_config_n(const char* _file_name, const char *_key, uint8_t _pos, char *_return_value){
    SHLink sconf_tmp = NULL;
    sconf_tmp = sconf_get_config_file_in_list(_file_name);
    if (sconf_tmp == NULL){
        sconf_debug(__func__, SCONF_DEBUG_WARNING, "configuration for (%s) is not exist or not opened yet.. process aborted!\n", _file_name);
        return -3;
    }
    SHLinkCustomData data_return;
    data_return.sl_key = NULL;
    data_return.sl_value = NULL;
    int8_t retval = 0;
    retval = shilink_search_data_by_position(
     sconf_tmp,
     (void *) _key,
     (uint16_t) strlen(_key),
     _pos,
     &data_return
    );
    if (retval != 0){
        sconf_debug(__func__, SCONF_DEBUG_WARNING, "can't found specific data\n");
        return -3;
    }
    if (data_return.sl_value == NULL){
        sconf_debug(__func__, SCONF_DEBUG_WARNING, "value is NULL\n");
        strcpy(_return_value, "");
        return -4;
    }
    strcpy(_return_value, data_return.sl_value);
    return 0;
}

int8_t sconf_get_config(const char* _file_name, const char *_key, char *_return_value){
    return sconf_get_config_n(_file_name, _key, 0, _return_value);
}

char *sconf_get_config_as_string_n(const char* _file_name, const char *_key, uint8_t _pos){
    SHLink sconf_tmp = NULL;
    sconf_tmp = sconf_get_config_file_in_list(_file_name);
    if (sconf_tmp == NULL){
        sconf_debug(__func__, SCONF_DEBUG_WARNING, "configuration for (%s) is not exist or not opened yet.. process aborted!\n", _file_name);
        return NULL;
    }
    SHLinkCustomData data_return;
    data_return.sl_key = NULL;
    data_return.sl_value = NULL;
    int8_t retval = 0;
    retval = shilink_search_data_by_position(
     sconf_tmp,
     (void *) _key,
     (uint16_t) strlen(_key),
     _pos,
     &data_return
    );
    if (retval != 0){
        sconf_debug(__func__, SCONF_DEBUG_WARNING, "can't found specific data\n");
        return NULL;
    }
    if (data_return.sl_value == NULL){
        sconf_debug(__func__, SCONF_DEBUG_WARNING, "value is NULL\n");
        return NULL;
    }
    return (char *) data_return.sl_value;
}

char *sconf_get_config_as_string(const char* _file_name, const char *_key){
    return sconf_get_config_as_string_n(_file_name, _key, 0);
}

int sconf_get_config_as_int_n(const char* _file_name, const char *_key, uint8_t _pos){
    char *conf_as_str = sconf_get_config_as_string_n(_file_name, _key, _pos);
    if (conf_as_str == NULL){
        return 0;
    }
    else {
        return atoi(conf_as_str);
    }
}

int sconf_get_config_as_int(const char* _file_name, const char *_key){
    return sconf_get_config_as_int_n(_file_name, _key, 0);
}

long sconf_get_config_as_long_n(const char* _file_name, const char *_key, uint8_t _pos){
    char *conf_as_str = sconf_get_config_as_string_n(_file_name, _key, _pos);
    if (conf_as_str == NULL){
        return 0;
    }
    else {
        return atol(conf_as_str);
    }
}

long sconf_get_config_as_long(const char* _file_name, const char *_key){
    return sconf_get_config_as_long_n(_file_name, _key, 0);
}

long long sconf_get_config_as_long_long_n(const char* _file_name, const char *_key, uint8_t _pos){
    char *conf_as_str = sconf_get_config_as_string_n(_file_name, _key, _pos);
    if (conf_as_str == NULL){
        return 0;
    }
    else {
        return atoll(conf_as_str);
    }
}

long long sconf_get_config_as_long_long(const char* _file_name, const char *_key){
    return sconf_get_config_as_long_long_n(_file_name, _key, 0);
}

float sconf_get_config_as_float_n(const char* _file_name, const char *_key, uint8_t _pos){
    char *conf_as_str = sconf_get_config_as_string_n(_file_name, _key, _pos);
    if (conf_as_str == NULL){
        return 0;
    }
    else {
        return atof(conf_as_str);
    }
}

float sconf_get_config_as_float(const char* _file_name, const char *_key){
    return sconf_get_config_as_float_n(_file_name, _key, 0);
}

static int8_t sconf_update_config(
 const char* _file_name,
 sconf_rules _rules,
 const char* _old_key,
 const char* _new_key,
 const char* _old_value,
 const char* _new_value
){
    SHLink sconf_tmp = NULL;
    sconf_tmp = sconf_get_config_file_in_list(_file_name);
    if (sconf_tmp == NULL){
        sconf_debug(__func__, SCONF_DEBUG_WARNING, "configuration for (%s) is not exist or not opened yet.. process aborted!\n", _file_name);
        return -3;
    }

    if (strcmp(_old_key, _new_key) != 0){
        if (_rules == SCONF_RULES_REFUSE_DUPLICATE_KEY){
            char value[SCONF_MAX_BUFF];
            if (sconf_get_config_n(_file_name, _new_key, 0, value) == 0){
              sconf_debug(__func__, SCONF_DEBUG_WARNING, "key %s in %s already exist. process aborted\n",
             _new_key, _file_name
             );
             return -8;
            }
            char key_tmp[strlen(_new_key) + 2];
            memset(key_tmp, 0x00, (strlen(_new_key) + 2) * sizeof(char));
            key_tmp[0] = SCONF_DISABLE_FLAG;
            strcat(key_tmp, _new_key);
            if (sconf_get_config_n(_file_name, key_tmp, 0, value) == 0){
              sconf_debug(__func__, SCONF_DEBUG_WARNING, "key %s in %s already exist, but disabled. process aborted\n",
             _new_key, _file_name
             );
             return -9;
            }
        }
    }

    SHLinkCustomData data_old, data_new;
    
    shilink_fill_custom_data(
     &data_old,
     (void *) _old_key,
     (uint16_t) strlen(_old_key),
     (void *) _old_value,
     (uint16_t) strlen(_old_value),
     SL_TEXT
    );
    shilink_fill_custom_data(
     &data_new,
     (void *) _new_key,
     (uint16_t) strlen(_new_key),
     (void *) _new_value,
     (uint16_t) strlen(_new_value),
     SL_TEXT
    );

    int8_t retval = 0;
    retval = shilink_update(&sconf_tmp, data_old, data_new);
    if (retval == -2){
        sconf_debug(__func__, SCONF_DEBUG_WARNING, "can't found specific data\n");
        return -3;
    }
    else if (retval == -1){
        sconf_debug(__func__, SCONF_DEBUG_ERROR, "process failed\n");
        return -4;
    }
    sconf_debug(__func__, SCONF_DEBUG_INFO, "success to update data\n");
    return 0;
}

int8_t sconf_update_config_keyword_and_value(
 const char* _file_name,
 sconf_rules _rules,
 const char* _old_key,
 const char* _new_key,
 const char* _old_value,
 const char* _new_value
){
    return sconf_update_config(_file_name, _rules, _old_key, _new_key, _old_value, _new_value);
}

int8_t sconf_update_config_value(
 const char* _file_name,
 sconf_rules _rules,
 const char* _key,
 const char* _value, ...
){
    va_list aptr;
    char *new_value = NULL;
    new_value = (char *) malloc(SCONF_MAX_BUFF*sizeof(char));
    if (new_value == NULL){
        sconf_debug(__func__, SCONF_DEBUG_ERROR, "failed to allocate new_value memory\n");
        return -3;
    }
    memset (new_value, 0x00, SCONF_MAX_BUFF*sizeof(char));
	va_start(aptr, _value);
	vsnprintf(new_value, (SCONF_MAX_BUFF - 1), _value, aptr);
	va_end(aptr);

    if (strlen(new_value) > (SCONF_MAX_BUFF - 1)){
        sconf_debug(__func__, SCONF_DEBUG_WARNING, "new_value memory overflow\n");
    }

    new_value = (char *) realloc(new_value, (strlen(new_value) + 1));

    int8_t retval = sconf_update_config(_file_name, _rules, _key, _key, NULL, new_value);
    
    free(new_value);
    new_value = NULL;

    return retval;
}

int8_t sconf_update_config_keyword(
 const char* _file_name,
 sconf_rules _rules,
 const char* _old_key,
 const char* _new_key, ...
){
    char *curent_value = NULL;
    curent_value = (char *) malloc(SCONF_MAX_BUFF*sizeof(char));
    if (curent_value == NULL){
        sconf_debug(__func__, SCONF_DEBUG_ERROR, "failed to allocate new_key memory\n");
        return -3;
    }

    memset(curent_value, 0x00, SCONF_MAX_BUFF*sizeof(char));

    if (sconf_get_config(_file_name, _old_key, curent_value) != 0){
        sconf_debug(__func__, SCONF_DEBUG_WARNING, "can't found specific data\n");
        free(curent_value);
        curent_value = NULL;
        return -4;
    }

    if (strlen(curent_value) > (SCONF_MAX_BUFF - 1)){
        sconf_debug(__func__, SCONF_DEBUG_WARNING, "new_key memory overflow\n");
    }

    curent_value = (char *) realloc(curent_value, (strlen(curent_value) + 1));

    va_list aptr;
    char *new_key = NULL;
    new_key = (char *) malloc(SCONF_MAX_BUFF*sizeof(char));
    if (new_key == NULL){
        sconf_debug(__func__, SCONF_DEBUG_ERROR, "failed to allocate new_key memory\n");
        free(curent_value);
        curent_value = NULL;
        return -3;
    }
    memset (new_key, 0x00, SCONF_MAX_BUFF*sizeof(char));
	va_start(aptr, _new_key);
	vsnprintf(new_key, (SCONF_MAX_BUFF - 1), _new_key, aptr);
	va_end(aptr);

    if (strlen(new_key) > (SCONF_MAX_BUFF - 1)){
        sconf_debug(__func__, SCONF_DEBUG_WARNING, "new_key memory overflow\n");
    }

    new_key = (char *) realloc(new_key, (strlen(new_key) + 1));

    int retval = sconf_update_config(_file_name, _rules, _old_key, new_key, curent_value, curent_value);

    free(curent_value);
    free(new_key);
    curent_value = NULL;
    new_key = NULL;

    return retval;
}

static int8_t sconf_remove_config(const char* _file_name, const char* _key, const char* _value){
    SHLink sconf_tmp = NULL;
    sconf_tmp = sconf_get_config_file_in_list(_file_name);
    if (sconf_tmp == NULL){
        sconf_debug(__func__, SCONF_DEBUG_WARNING, "configuration for (%s) is not exist or not opened yet.. process aborted!\n", _file_name);
        return -3;
    }

    SHLinkCustomData data_rm;
    shilink_fill_custom_data(
     &data_rm,
     (void *) _key,
     (uint16_t) strlen(_key),
     (void *) _value,
     (uint16_t) strlen(_value),
     SL_TEXT
    );

    int8_t retval = 0;
    retval = shilink_delete(&sconf_tmp, data_rm);
    if (retval != 0){
        sconf_debug(__func__, SCONF_DEBUG_WARNING, "can't found specific data\n");
        return -3;
    }
    return 0;
}

int8_t sconf_remove_config_by_keyword(const char* _file_name, const char* _key, ...){
    va_list aptr;
    char *keyword = NULL;
    keyword = (char *) malloc(SCONF_MAX_BUFF*sizeof(char));
    if (keyword == NULL){
        sconf_debug(__func__, SCONF_DEBUG_ERROR, "failed to allocate keyword memory\n");
        return -3;
    }
    memset (keyword, 0x00, SCONF_MAX_BUFF*sizeof(char));
	va_start(aptr, _key);
	vsnprintf(keyword, (SCONF_MAX_BUFF - 1), _key, aptr);
	va_end(aptr);

    if (strlen(keyword) > (SCONF_MAX_BUFF - 1)){
        sconf_debug(__func__, SCONF_DEBUG_WARNING, "keyword memory overflow\n");
    }

    keyword = (char *) realloc(keyword, (strlen(keyword) + 1));

    SHLinkCustomData data_rm;
    shilink_fill_custom_data(
     &data_rm,
     (void *) keyword,
     (uint16_t) strlen(keyword),
     NULL,
     0,
     SL_TEXT
    );

    int8_t retval = sconf_remove_config(_file_name, keyword, NULL);

    free(keyword);
    keyword = NULL;

    return retval;
}

int8_t sconf_remove_config_by_keyword_and_value(const char* _file_name, const char* _key, const char* _value){
    return sconf_remove_config(_file_name, _key, _value);
}

int8_t sconf_get_additional_information(const char *_file_name, char *_aditional_data, uint16_t _max_data_to_get){
    return sconf_get_config_n(_file_name, "add_info", 0, _aditional_data);
}

int8_t sconf_update_additional_information(const char *_file_name, const char *_new_additional_data){
    return sconf_update_config_value(_file_name, SCONF_RULES_REFUSE_DUPLICATE_KEY, "add_info", _new_additional_data);
}

int8_t sconf_set_additional_information(const char *_file_name, const char *_additional_data){
    return sconf_insert_config(_file_name, SCONF_RULES_REFUSE_DUPLICATE_KEY, "add_info", _additional_data);
}

int8_t sconf_disable_config_by_keyword(const char *_file_name, const char *_key){
    char key_tmp[strlen(_key) + 2];
    memset(key_tmp, 0x00, (strlen(_key) + 2) * sizeof(char));
    key_tmp[0] = SCONF_DISABLE_FLAG;
    strcat(key_tmp, _key);
    return sconf_update_config_keyword(_file_name, SCONF_RULES_ALLOW_DUPLICATE_KEY,_key, key_tmp);
}

int8_t sconf_enable_config_by_keyword(const char *_file_name, const char *_key){
    char key_tmp[strlen(_key) + 2];
    memset(key_tmp, 0x00, (strlen(_key) + 2) * sizeof(char));
    key_tmp[0] = SCONF_DISABLE_FLAG;
    strcat(key_tmp, _key);
    return sconf_update_config_keyword(_file_name, SCONF_RULES_ALLOW_DUPLICATE_KEY, key_tmp, _key);
}

int8_t sconf_disable_config_by_keyword_and_value(const char *_file_name, const char *_key, const char *_value){
    char key_tmp[strlen(_key) + 2];
    memset(key_tmp, 0x00, (strlen(_key) + 2) * sizeof(char));
    key_tmp[0] = SCONF_DISABLE_FLAG;
    strcat(key_tmp, _key);
    return sconf_update_config_keyword_and_value(_file_name, SCONF_RULES_ALLOW_DUPLICATE_KEY, _key, key_tmp, _value, _value);
}

int8_t sconf_enable_config_by_keyword_and_value(const char *_file_name, const char *_key, const char *_value){
    char key_tmp[strlen(_key) + 2];
    memset(key_tmp, 0x00, (strlen(_key) + 2) * sizeof(char));
    key_tmp[0] = SCONF_DISABLE_FLAG;
    strcat(key_tmp, _key);
    return sconf_update_config_keyword_and_value(_file_name, SCONF_RULES_ALLOW_DUPLICATE_KEY, key_tmp, _key, _value, _value);
}

int8_t sconf_generate_new_config_start(const char *_file_name){
    SHLink sconf_tmp = NULL;
    sconf_tmp = sconf_get_config_file_in_list(_file_name);
    if (sconf_tmp != NULL){
        sconf_debug(__func__, SCONF_DEBUG_WARNING, "configuration for (%s) is alreadey set/used.. process aborted!\n", _file_name);
        return -3;
    }

    SHLinkCustomData conf_data;
    if (shilink_fill_custom_data(
     &conf_data,
     (void *) "SCONF_FILE_NAME",
     15,
     (void *) _file_name,
     (uint16_t) strlen(_file_name),
     SL_TEXT
    ) != 0){
        sconf_debug(__func__, SCONF_DEBUG_ERROR, "failed to start to generate new config\n");
        return -2;
    }

    if (shilink_append(&sconf_tmp, conf_data) != 0){
        sconf_debug(__func__, SCONF_DEBUG_ERROR, "failed to start to generate new config\n");
        return -3;
    }

    if (shilink_fill_custom_data(
     &conf_data,
     (void *) "[END]",
     5,
     NULL,
     0,
     SL_POINTER
    ) != 0){
        sconf_debug(__func__, SCONF_DEBUG_ERROR, "failed to start to generate new config\n");
        shilink_free(&sconf_tmp);
        sconf_tmp = NULL;
        return -3;
    }

    if (shilink_append(&sconf_tmp, conf_data) != 0){
        sconf_debug(__func__, SCONF_DEBUG_ERROR, "failed to start to generate new config\n");
        shilink_free(&sconf_tmp);
        shilink_free_custom_data(&conf_data);
        sconf_tmp = NULL;
        return -2;
    }
    if (sconf_add_file(_file_name, sconf_tmp)){
        shilink_free(&sconf_tmp);
        sconf_tmp = NULL;
        sconf_debug(__func__, SCONF_DEBUG_ERROR, "failed to copy list for %s. process aborted!\n", _file_name);
        return -4;
    }
    return 0;
}

int8_t sconf_insert_config(const char *_file_name, sconf_rules _rules, const char *_key, const char *_value, ...){
    SHLink sconf_tmp = NULL;
    sconf_tmp = sconf_get_config_file_in_list(_file_name);
    if (sconf_tmp == NULL){
        sconf_debug(__func__, SCONF_DEBUG_WARNING, "configuration for (%s) is not exist or not opened yet.. process aborted!\n", _file_name);
        return -3;
    }

    if (_rules == SCONF_RULES_REFUSE_DUPLICATE_KEY){
        char value[SCONF_MAX_BUFF];
        if (sconf_get_config_n(_file_name, _key, 0, value) == 0){
          sconf_debug(__func__, SCONF_DEBUG_WARNING, "key %s in %s already exist. process aborted\n",
          _key, _file_name
         );
         return -8;
        }
        char key_tmp[strlen(_key) + 2];
        memset(key_tmp, 0x00, (strlen(_key) + 2) * sizeof(char));
        key_tmp[0] = SCONF_DISABLE_FLAG;
        strcat(key_tmp, _key);
        if (sconf_get_config_n(_file_name, key_tmp, 0, value) == 0){
          sconf_debug(__func__, SCONF_DEBUG_WARNING, "key %s in %s already exist, but disabled. process aborted\n",
          _key, _file_name
         );
         return -9;
        }
    }

    va_list aptr;
    char *new_value = NULL;
    new_value = (char *) malloc(SCONF_MAX_BUFF*sizeof(char));
    if (new_value == NULL){
        sconf_debug(__func__, SCONF_DEBUG_ERROR, "failed to allocate new_value memory\n");
        return -3;
    }
    memset (new_value, 0x00, SCONF_MAX_BUFF*sizeof(char));
	va_start(aptr, _value);
	vsnprintf(new_value, (SCONF_MAX_BUFF - 1), _value, aptr);
	va_end(aptr);

    if (strlen(new_value) > (SCONF_MAX_BUFF - 1)){
        sconf_debug(__func__, SCONF_DEBUG_WARNING, "new_value memory overflow\n");
    }

    new_value = (char *) realloc(new_value, (strlen(new_value) + 1));

    SHLinkCustomData conf_data, cond_data;

    if (shilink_fill_custom_data(
     &cond_data,
     "[END]",
     5,
     NULL,
     0,
     SL_POINTER
    ) != 0){
        sconf_debug(__func__, SCONF_DEBUG_ERROR, "failed to insert new config (1)\n");
        return -3;
    }

    if (shilink_fill_custom_data(
     &conf_data,
     (void *) _key,
     (uint16_t) strlen(_key),
     (void *) new_value,
     (uint16_t) strlen(new_value),
     SL_TEXT
    ) != 0){
        sconf_debug(__func__, SCONF_DEBUG_ERROR, "failed to insert new config (2)\n");
        shilink_free_custom_data(&cond_data);
        return -4;
    }
    free(new_value);
    new_value = NULL;

    if (strcmp(_key, "add_info") != 0){
        if (shilink_insert_before(&sconf_tmp, cond_data, conf_data) != 0){
            if (shilink_append(&sconf_tmp, conf_data) != 0){
                sconf_debug(__func__, SCONF_DEBUG_ERROR, "failed to insert new config (3)\n");
                shilink_free_custom_data(&cond_data);
                return -5;
            }
        }
    }
    else {
        if (shilink_insert_after(&sconf_tmp, cond_data, conf_data) != 0){
            sconf_debug(__func__, SCONF_DEBUG_ERROR, "failed to insert new config (3)\n");
            shilink_free_custom_data(&cond_data);
            return -5;
        }
    }

    shilink_free_custom_data(&cond_data);

    if (strcmp(_key, "add_info") != 0){
        sconf_debug(__func__, SCONF_DEBUG_INFO, "success to insert %s%c%s as new config\n", _key, new_value);
    }
    else {
        sconf_debug(__func__, SCONF_DEBUG_INFO, "success to insert additional information\n");
    }
    return 0;
}

static int8_t sconf_write_config(
 const char *_file_name,
 const char *_file_alias,
 char *_valid_checksum,
 sconf_purpose_parameter _param
){
    SHLink sconf_tmp = NULL;
    sconf_tmp = sconf_get_config_file_in_list(_file_name);
    if (sconf_tmp == NULL){
        sconf_debug(__func__, SCONF_DEBUG_WARNING, "configuration for (%s) is not exist or not opened yet.. process aborted!\n", _file_name);
        return -3;
    }

    if(strcmp(sconf_tmp->sl_data.sl_value, _file_name) != 0){
        sconf_debug(__func__, SCONF_DEBUG_WARNING, "current config is not \"%s\", but \"%s\"\n",
         _file_name, sconf_tmp->sl_data.sl_value
        );
        return -2;
    }

    FILE *conf_file = NULL;
    uint8_t try_times = SCONF_OPEN_TRY_TIMES;

    do{
        if (_param == SCONF_CREATE_PURPOSE){
            conf_file = fopen(_file_alias, "r");
        }
        else if (_param == SCONF_UPDATE_PURPOSE){
            conf_file = fopen(_file_name, "r");
        }
        else if (_param == SCONF_FORCE_WRITE){
            break;
        }
        try_times--;
    } while (conf_file == NULL && try_times > 0);

    if (_param == SCONF_CREATE_PURPOSE){
        if (conf_file != NULL){
            sconf_debug(__func__, SCONF_DEBUG_ERROR, "config file (%s) already exist. process aborted\n", _file_alias);
            fclose(conf_file);
            return -1;
        }
    }
    else if (_param == SCONF_UPDATE_PURPOSE){
        if (conf_file == NULL){
            sconf_debug(__func__, SCONF_DEBUG_ERROR, "config file (%s) isn't exist. process aborted\n", _file_name);
            return -1;
        }
        fclose(conf_file);
    }

    try_times = SCONF_OPEN_TRY_TIMES;

    do{
    	conf_file = fopen(_file_alias, "w");
        try_times--;
    } while (conf_file == NULL && try_times > 0);

    if (conf_file == NULL){
        sconf_debug(__func__, SCONF_DEBUG_ERROR, "failed to write %s.\n", _file_alias);
        fclose(conf_file);
        return -2;
    }

    SHLinkCustomData data_conf;
    int8_t retval = 0;
    int8_t end_state = 0;
    int16_t idx_pos = 1;
    char sconf_bytes[2];
    unsigned char checksum_data[sizeof(long)];
    char checksum_str[2*(sizeof(long))+1];
    memset(checksum_data, 0x00, sizeof(checksum_data));
    memset(checksum_str, 0x00, sizeof(checksum_str));

    sconf_bytes[0] = SCONF_SEPARATOR;
    sconf_bytes[1] = 0x00;

    do {
        retval = shilink_get_data_by_position(sconf_tmp, idx_pos, &data_conf);
        if (retval == 0){
            if (end_state == 0){
                if (strcmp(data_conf.sl_key, "add_info") == 0){
                    fprintf(conf_file, "[END]\n%s", (char *) data_conf.sl_value);
                    sconf_append_data_checksum(checksum_data, (unsigned char *) "[END]\n", 6);
                    sconf_append_data_checksum(checksum_data, (unsigned char *) data_conf.sl_value, strlen(data_conf.sl_value));
                    break;
                }
                else if (strcmp(data_conf.sl_key, "[END]") == 0){
                    fprintf(conf_file, "%s\n", (char *) data_conf.sl_key);
                    sconf_append_data_checksum(checksum_data, (unsigned char *) "[END]\n", 6);
                    end_state = 1;
                }
                else if (strlen(data_conf.sl_value) == 0){
                    fprintf(conf_file, "%s\n", (char *) data_conf.sl_key);
                    sconf_append_data_checksum(checksum_data, (unsigned char *) data_conf.sl_key, strlen(data_conf.sl_key));
                    sconf_append_data_checksum(checksum_data, (unsigned char *) "\n", 1);
                }
                else if (strlen(data_conf.sl_value) > 0){
                    fprintf(conf_file, "%s%c%s\n", (char *) data_conf.sl_key, SCONF_SEPARATOR, (char *) data_conf.sl_value);
                    sconf_append_data_checksum(checksum_data, (unsigned char *) data_conf.sl_key, strlen(data_conf.sl_key));
                    sconf_append_data_checksum(checksum_data, (unsigned char *) sconf_bytes, 1);
                    sconf_append_data_checksum(checksum_data, (unsigned char *) data_conf.sl_value, strlen(data_conf.sl_value));
                    sconf_append_data_checksum(checksum_data, (unsigned char *) "\n", 1);
                }
            }
            else if (strcmp(data_conf.sl_key, "add_info") == 0){
                fprintf(conf_file, "%s", (char *) data_conf.sl_value);
                sconf_append_data_checksum(checksum_data, (unsigned char *) data_conf.sl_value, strlen(data_conf.sl_value));
                break;
            }
        }
        idx_pos++;
        if (idx_pos==32000){
            sconf_debug(__func__, SCONF_DEBUG_WARNING, "sconf reach the limit\n");
            break;
        }
    } while (retval == 0);

    fclose(conf_file);
    sconf_output_checksum_string(checksum_str, checksum_data);
    strcpy(_valid_checksum, checksum_str);
    return 0;
}

int8_t sconf_generate_new_config_end(const char *_file_name){
    char sconf_checksum[(2*sizeof(long))+1];
    char valid_checksum[(2*sizeof(long))+1];

    memset(sconf_checksum, 0x00, sizeof(sconf_checksum));
    memset(valid_checksum, 0x00, sizeof(valid_checksum));

    if (sconf_write_config(_file_name, _file_name, valid_checksum, SCONF_CREATE_PURPOSE) != 0){
        sconf_debug(__func__, SCONF_DEBUG_ERROR, "failed to end new config (%s)\n", _file_name);
        return -1;
    }

    sconf_get_checksum_file(_file_name, sconf_checksum);

    sconf_debug(__func__, SCONF_DEBUG_INFO, "checksum variable: %s\n", valid_checksum);
    sconf_debug(__func__, SCONF_DEBUG_INFO, "checksum file: %s\n", sconf_checksum);

    if (strcmp(valid_checksum, sconf_checksum) != 0){
        sconf_debug(__func__, SCONF_DEBUG_WARNING, "problem on checksum (%s)\n", _file_name);
    }
    return 0;
}

int8_t sconf_force_write_config(const char *_file_name){
    char sconf_checksum[(2*sizeof(long))+1];
    char valid_checksum[(2*sizeof(long))+1];

    memset(sconf_checksum, 0x00, sizeof(sconf_checksum));
    memset(valid_checksum, 0x00, sizeof(valid_checksum));

    if (sconf_write_config(_file_name, _file_name, valid_checksum, SCONF_FORCE_WRITE) != 0){
        sconf_debug(__func__, SCONF_DEBUG_ERROR, "failed to force config (%s)\n", _file_name);
        return -1;
    }

    sconf_get_checksum_file(_file_name, sconf_checksum);

    sconf_debug(__func__, SCONF_DEBUG_INFO, "checksum variable: %s\n", valid_checksum);
    sconf_debug(__func__, SCONF_DEBUG_INFO, "checksum file: %s\n", sconf_checksum);

    if (strcmp(valid_checksum, sconf_checksum) != 0){
        sconf_debug(__func__, SCONF_DEBUG_WARNING, "problem on checksum (%s)\n", _file_name);
    }
    return 0;
}

int8_t sconf_write_config_updates(const char *_file_name){
    char sconf_checksum[(2*sizeof(long))+1];
    char valid_checksum[(2*sizeof(long))+1];

    memset(sconf_checksum, 0x00, sizeof(sconf_checksum));
    memset(valid_checksum, 0x00, sizeof(valid_checksum));

    char tmp_file_name[strlen(_file_name) + 5];
    memset(tmp_file_name, 0x00, sizeof(tmp_file_name));
    sprintf(tmp_file_name, "%s.tmp", _file_name);

    if (sconf_write_config(_file_name, tmp_file_name, valid_checksum, SCONF_UPDATE_PURPOSE) != 0){
        sconf_debug(__func__, SCONF_DEBUG_ERROR, "failed to end new config (%s)\n", _file_name);
        return -1;
    }

    sconf_get_checksum_file(tmp_file_name, sconf_checksum);


    if (strcmp(valid_checksum, sconf_checksum) != 0){
        sconf_debug(__func__, SCONF_DEBUG_WARNING, "problem on checksum (%s). process aborted!\n", _file_name);
        return -2;
    }

    remove(_file_name);
    rename(tmp_file_name, _file_name);
    return 0;
}

int8_t sconf_release_config_list(const char *_file_name){
    SHLink sconf_tmp = NULL;
    sconf_tmp = sconf_get_config_file_in_list(_file_name);
    if (sconf_tmp == NULL){
        sconf_debug(__func__, SCONF_DEBUG_WARNING, "configuration for (%s) is not exist or not opened yet.. process aborted!\n", _file_name);
        return -3;
    }
    SHLinkCustomData data_deleted;
    shilink_free(&(sconf_tmp->sh_next));
    shilink_fill_custom_data(
     &data_deleted,
     (void *) _file_name,
     (uint16_t) (strlen(_file_name) % UINT16_MAX),
     NULL,
     0,
     SL_POINTER
    );
    if (shilink_delete(&sconf_list, data_deleted)){
        sconf_debug(__func__, SCONF_DEBUG_WARNING, "configuration for (%s) has been free, but failed to release from list.\n", _file_name);
        return -4;
    }
    return 0;
}