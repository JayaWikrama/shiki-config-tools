#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <time.h>

#include "shiki-config-tools.h"

#define sconf_get_var_name(_var) #_var

int8_t sconf_debug_mode_status = 1;

uint16_t SCONF_MAX_BUFF = 25;
uint8_t SCONF_OPEN_TRY_TIMES = 1;
char SCONF_SEPARATOR = '=';
char SCONF_DISABLE_FLAG = '#';

uint16_t SCONF_MAX_LINE_LENGTH = 200;
int8_t SCONF_SKIP_SPACE_FROM_LINE = SCONF_CHECK_WITH_SPACE;

static void sconf_debug(const char *function_name, char *debug_type, char *debug_msg, ...){
	if (sconf_debug_mode_status == 1){
        time_t debug_time;
	    struct tm *d_tm;
	    va_list aptr;
		
	    time(&debug_time);
	    d_tm = localtime(&debug_time);
	    char tmp_debug_msg[100];
	    va_start(aptr, debug_msg);
	    vsprintf(tmp_debug_msg, debug_msg, aptr);
	    va_end(aptr);
	
	    printf("%02d-%02d-%04d %02d:%02d:%02d %s: %s: %s", d_tm->tm_mday, d_tm->tm_mon+1, d_tm->tm_year+1900, d_tm->tm_hour, d_tm->tm_min, d_tm->tm_sec, debug_type, function_name, tmp_debug_msg);
    }
}

// COMMON FUNCTION STD CONFIG : _KEY=_VALUE

int8_t sconf_setup(sconf_setup_parameter _parameters, uint16_t _value){
    if (_parameters == SCONF_SET_DEBUG_MODE){
        if (_value == SCONF_DEBUG_OFF || _value == SCONF_DEBUG_ON){
            sconf_debug_mode_status = _value;
        }
        else {
            sconf_debug(__func__, "WARNING", "invalid value\n");
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
        sconf_debug(__func__, "WARNING", "invalid parameters\n");
    }
    return 0;
}

int8_t sconf_get_config(char* _file_name, char *_key, char *_return_value){
    FILE *conf_file;
    uint8_t try_times = SCONF_OPEN_TRY_TIMES;

    do{
    	conf_file = fopen(_file_name, "r");
        try_times--;
    } while (conf_file == NULL && try_times > 0);

    if (conf_file == NULL){
        sconf_debug(__func__, "ERROR", "failed to open config file\n");
        return -1;
    }

	char buff_init[SCONF_MAX_BUFF], buff_conf[SCONF_MAX_BUFF];
	char character = 0;
	uint16_t idx_char = 0;
	uint16_t idx_conf = 0;
	memset(buff_init, 0x00, SCONF_MAX_BUFF*sizeof(char));
	memset(buff_conf, 0x00, SCONF_MAX_BUFF*sizeof(char));
	
	while((character = fgetc(conf_file)) != EOF){
		if (character > 127) break;
		if (character == '\n' || idx_char == SCONF_MAX_BUFF){
			if(strcmp(buff_init, _key) == 0){
				strcpy(_return_value, buff_conf);
                fclose(conf_file);
                return 0;
			}
			else if(strncmp(buff_init, "[END]", strlen("[END]")) == 0){
				memset(buff_init, 0x00, SCONF_MAX_BUFF*sizeof(char));
				memset(buff_conf, 0x00, SCONF_MAX_BUFF*sizeof(char));
                idx_conf=idx_char=0;
                break;
			}
			memset(buff_init, 0x00, SCONF_MAX_BUFF*sizeof(char));
			memset(buff_conf, 0x00, SCONF_MAX_BUFF*sizeof(char));
			idx_conf=idx_char=0;
		}
		else if(idx_conf==0 && character != SCONF_SEPARATOR){
			buff_init[idx_char] = character;
			idx_char++;
		}
		else if(idx_conf==1 && character != SCONF_SEPARATOR){
			buff_conf[idx_char] = character;
			idx_char++;
		}
		else if(character == SCONF_SEPARATOR){
			idx_char = 0;
			idx_conf = 1;
		}
	}
	fclose(conf_file);
	return 1;
}

int8_t sconf_update_config(char* _file_name, char* _key, char* _value, ...){
    FILE *conf_file;
    uint8_t try_times = SCONF_OPEN_TRY_TIMES;

    // open existing file
    do{
    	conf_file = fopen(_file_name, "r");
        try_times--;
    } while (conf_file == NULL && try_times > 0);

    if (conf_file == NULL){
        sconf_debug(__func__, "ERROR", "failed to open config file\n");
        return -1;
    }

    char character = 0;
    char buff_init[SCONF_MAX_BUFF];
    uint16_t idx_char;
    memset(buff_init, 0x00, SCONF_MAX_BUFF*sizeof(char));

    while((character = fgetc(conf_file)) != EOF){
		if (character > 127) break;
		if (character == '\n' || character == SCONF_SEPARATOR || idx_char == SCONF_MAX_BUFF){
			if(strcmp(buff_init, _key) == 0){
                break;
			}
			memset(buff_init, 0x00, SCONF_MAX_BUFF*sizeof(char));
            idx_char = 0;
		}
        else{
            buff_init[idx_char] = character;
            idx_char++;
        }
	}

    if (strcmp(_key, buff_init) != 0){
        sconf_debug(__func__, "ERROR", "keyword not found. process aborted\n");
        fclose(conf_file);
        return -1;
    }

    fseek(conf_file, 0, SEEK_SET);    

    // open new file
    FILE *update_file;
    try_times = SCONF_OPEN_TRY_TIMES;

    char tmp_file_name[strlen(_file_name) + 5];
    memset(tmp_file_name, 0x00, (strlen(_file_name) + 5) *sizeof(char));
    sprintf(tmp_file_name, "%s.tmp", _file_name);

    do{
    	update_file = fopen(tmp_file_name, "w");
        try_times--;
    } while (update_file == NULL && try_times > 0);

    if (update_file == NULL){
        sconf_debug(__func__, "ERROR", "failed to create new config file\n");
        fclose(conf_file);
        return -2;
    }

    va_list aptr;
    char writen_value[SCONF_MAX_BUFF];
    memset (writen_value, 0x00, SCONF_MAX_BUFF*sizeof(char));
	va_start(aptr, _value);
	vsprintf(writen_value, _value, aptr);
	va_end(aptr);

	char buff_conf[SCONF_MAX_BUFF];
	character = 0;
	idx_char = 0;
	uint16_t idx_conf = 0;
    int8_t conf_cond = 0;
	memset(buff_init, 0x00, SCONF_MAX_BUFF*sizeof(char));
	memset(buff_conf, 0x00, SCONF_MAX_BUFF*sizeof(char));
	
	while((character = fgetc(conf_file)) != EOF){
		if (character > 127) break;
		if ((character == '\n'  || idx_char == SCONF_MAX_BUFF) && conf_cond == 0){
			if(strcmp(buff_init, _key) == 0){
                fprintf(update_file, "%s%c%s\n", buff_init, SCONF_SEPARATOR, writen_value);
			}
			else if(strncmp(buff_init, "[END]", strlen("[END]")) == 0){
                fprintf(update_file, "[END]\n");
                conf_cond = 1;
				memset(buff_init, 0x00, SCONF_MAX_BUFF*sizeof(char));
				memset(buff_conf, 0x00, SCONF_MAX_BUFF*sizeof(char));
                idx_conf=idx_char=0;
			}
            else {
                fprintf(update_file, "%s%c%s\n", buff_init, SCONF_SEPARATOR, buff_conf);
            }
			memset(buff_init, 0x00, SCONF_MAX_BUFF*sizeof(char));
			memset(buff_conf, 0x00, SCONF_MAX_BUFF*sizeof(char));
			idx_conf=idx_char=0;
		}
		else if(idx_conf==0 && character != SCONF_SEPARATOR && conf_cond == 0){
			buff_init[idx_char] = character;
			idx_char++;
		}
		else if(idx_conf==1 && character != SCONF_SEPARATOR && conf_cond == 0){
			buff_conf[idx_char] = character;
			idx_char++;
		}
		else if(character == SCONF_SEPARATOR && conf_cond == 0){
			idx_char = 0;
			idx_conf = 1;
		}
        else if (conf_cond == 1){
            fprintf(update_file, "%c", character);
        }
	}
	fclose(conf_file);
    fclose(update_file);
    remove(_file_name);
    rename(tmp_file_name, _file_name);
    return 0;
}

int8_t sconf_update_keyword(char* _file_name, char* _old_key, char* _new_key){
    FILE *conf_file;
    uint8_t try_times = SCONF_OPEN_TRY_TIMES;

    // open existing file
    do{
    	conf_file = fopen(_file_name, "r");
        try_times--;
    } while (conf_file == NULL && try_times > 0);

    if (conf_file == NULL){
        sconf_debug(__func__, "ERROR", "failed to open config file\n");
        return -1;
    }

    char character = 0;
    char buff_init[SCONF_MAX_BUFF];
    uint16_t idx_char;
    memset(buff_init, 0x00, SCONF_MAX_BUFF*sizeof(char));

    while((character = fgetc(conf_file)) != EOF){
		if (character > 127) break;
		if (character == '\n' || character == SCONF_SEPARATOR || idx_char == SCONF_MAX_BUFF){
			if (strcmp(buff_init, _new_key) == 0){
                fclose(conf_file);
                sconf_debug(__func__, "ERROR", "keyword \"%s\" already exist. process aborted\n", buff_init);
                return -1;
			}
            else if(strcmp(buff_init, _old_key) == 0){
                break;
			}
			memset(buff_init, 0x00, SCONF_MAX_BUFF*sizeof(char));
            idx_char = 0;
		}
        else{
            buff_init[idx_char] = character;
            idx_char++;
        }
	}

    if (strcmp(_old_key, buff_init) != 0){
        sconf_debug(__func__, "ERROR", "keyword not found. process aborted\n");
        fclose(conf_file);
        return -1;
    }

    fseek(conf_file, 0, SEEK_SET);    

    // open new file
    FILE *update_file;
    try_times = SCONF_OPEN_TRY_TIMES;

    char tmp_file_name[strlen(_file_name) + 5];
    memset(tmp_file_name, 0x00, (strlen(_file_name) + 5) *sizeof(char));
    sprintf(tmp_file_name, "%s.tmp", _file_name);

    do{
    	update_file = fopen(tmp_file_name, "w");
        try_times--;
    } while (update_file == NULL && try_times > 0);

    if (update_file == NULL){
        sconf_debug(__func__, "ERROR", "failed to create new config file\n");
        fclose(conf_file);
        return -2;
    }

	char buff_conf[SCONF_MAX_BUFF];
	character = 0;
	idx_char = 0;
	uint16_t idx_conf = 0;
    int8_t conf_cond = 0;
	memset(buff_init, 0x00, SCONF_MAX_BUFF*sizeof(char));
	memset(buff_conf, 0x00, SCONF_MAX_BUFF*sizeof(char));
	
	while((character = fgetc(conf_file)) != EOF){
		if (character > 127) break;
		if ((character == '\n' || idx_char == SCONF_MAX_BUFF) && conf_cond == 0){
			if(strcmp(buff_init, _old_key) == 0){
                fprintf(update_file, "%s%c%s\n", _new_key, SCONF_SEPARATOR, buff_conf);
			}
			else if(strncmp(buff_init, "[END]", strlen("[END]")) == 0){
                fprintf(update_file, "[END]\n");
                conf_cond = 1;
				memset(buff_init, 0x00, SCONF_MAX_BUFF*sizeof(char));
				memset(buff_conf, 0x00, SCONF_MAX_BUFF*sizeof(char));
                idx_conf=idx_char=0;
			}
            else {
                fprintf(update_file, "%s%c%s\n", buff_init, SCONF_SEPARATOR, buff_conf);
            }
			memset(buff_init, 0x00, SCONF_MAX_BUFF*sizeof(char));
			memset(buff_conf, 0x00, SCONF_MAX_BUFF*sizeof(char));
			idx_conf=idx_char=0;
		}
		else if(idx_conf==0 && character != SCONF_SEPARATOR && conf_cond == 0){
			buff_init[idx_char] = character;
			idx_char++;
		}
		else if(idx_conf==1 && character != SCONF_SEPARATOR && conf_cond == 0){
			buff_conf[idx_char] = character;
			idx_char++;
		}
		else if(character == SCONF_SEPARATOR && conf_cond == 0){
			idx_char = 0;
			idx_conf = 1;
		}
        else if (conf_cond == 1){
            fprintf(update_file, "%c", character);
        }
	}
	fclose(conf_file);
    fclose(update_file);
    remove(_file_name);
    rename(tmp_file_name, _file_name);
    return 0;
}

int8_t sconf_remove_config(char* _file_name, char* _key){
    FILE *conf_file;
    uint8_t try_times = SCONF_OPEN_TRY_TIMES;

    // open existing file
    do{
    	conf_file = fopen(_file_name, "r");
        try_times--;
    } while (conf_file == NULL && try_times > 0);

    if (conf_file == NULL){
        sconf_debug(__func__, "ERROR", "failed to open config file\n");
        return -1;
    }

    char character = 0;
    char buff_init[SCONF_MAX_BUFF];
    uint16_t idx_char;
    memset(buff_init, 0x00, SCONF_MAX_BUFF*sizeof(char));

    while((character = fgetc(conf_file)) != EOF){
		if (character > 127) break;
		if (character == '\n' || character == SCONF_SEPARATOR || idx_char == SCONF_MAX_BUFF){
			if(strcmp(buff_init, _key) == 0){
                break;
			}
			memset(buff_init, 0x00, SCONF_MAX_BUFF*sizeof(char));
            idx_char = 0;
		}
        else{
            buff_init[idx_char] = character;
            idx_char++;
        }
	}

    if (strcmp(_key, buff_init) != 0){
        sconf_debug(__func__, "ERROR", "keyword not found. process aborted\n");
        fclose(conf_file);
        return -1;
    }

    fseek(conf_file, 0, SEEK_SET);    

    // open new file
    FILE *update_file;
    try_times = SCONF_OPEN_TRY_TIMES;

    char tmp_file_name[strlen(_file_name) + 5];
    memset(tmp_file_name, 0x00, (strlen(_file_name) + 5) *sizeof(char));
    sprintf(tmp_file_name, "%s.tmp", _file_name);

    do{
    	update_file = fopen(tmp_file_name, "w");
        try_times--;
    } while (update_file == NULL && try_times > 0);

    if (update_file == NULL){
        sconf_debug(__func__, "ERROR", "failed to create new config file\n");
        fclose(conf_file);
        return -2;
    }

	char buff_conf[SCONF_MAX_BUFF];
	character = 0;
	idx_char = 0;
	uint16_t idx_conf = 0;
    int8_t conf_cond = 0;
	memset(buff_init, 0x00, SCONF_MAX_BUFF*sizeof(char));
	memset(buff_conf, 0x00, SCONF_MAX_BUFF*sizeof(char));
	
	while((character = fgetc(conf_file)) != EOF){
		if (character > 127) break;
		if ((character == '\n' || idx_char == SCONF_MAX_BUFF) && conf_cond == 0){
			if(strcmp(buff_init, _key) == 0){
                // do noting
			}
			else if(strncmp(buff_init, "[END]", strlen("[END]")) == 0){
                fprintf(update_file, "[END]\n");
                conf_cond = 1;
				memset(buff_init, 0x00, SCONF_MAX_BUFF*sizeof(char));
				memset(buff_conf, 0x00, SCONF_MAX_BUFF*sizeof(char));
                idx_conf=idx_char=0;
			}
            else {
                fprintf(update_file, "%s%c%s\n", buff_init, SCONF_SEPARATOR, buff_conf);
            }
			memset(buff_init, 0x00, SCONF_MAX_BUFF*sizeof(char));
			memset(buff_conf, 0x00, SCONF_MAX_BUFF*sizeof(char));
			idx_conf=idx_char=0;
		}
		else if(idx_conf==0 && character != SCONF_SEPARATOR && conf_cond == 0){
			buff_init[idx_char] = character;
			idx_char++;
		}
		else if(idx_conf==1 && character != SCONF_SEPARATOR && conf_cond == 0){
			buff_conf[idx_char] = character;
			idx_char++;
		}
		else if(character == SCONF_SEPARATOR && conf_cond == 0){
			idx_char = 0;
			idx_conf = 1;
		}
        else if (conf_cond == 1){
            fprintf(update_file, "%c", character);
        }
	}
	fclose(conf_file);
    fclose(update_file);
    remove(_file_name);
    rename(tmp_file_name, _file_name);
    return 0;
}

int8_t sconf_remove_broken_config(char* _file_name){
    FILE *conf_file;
    uint8_t try_times = SCONF_OPEN_TRY_TIMES;

    // open existing file
    do{
    	conf_file = fopen(_file_name, "r");
        try_times--;
    } while (conf_file == NULL && try_times > 0);

    if (conf_file == NULL){
        sconf_debug(__func__, "ERROR", "failed to open config file\n");
        return -1;
    }

    // open new file
    FILE *update_file;
    try_times = SCONF_OPEN_TRY_TIMES;

    char tmp_file_name[strlen(_file_name) + 5];
    memset(tmp_file_name, 0x00, (strlen(_file_name) + 5) *sizeof(char));
    sprintf(tmp_file_name, "%s.tmp", _file_name);

    do{
    	update_file = fopen(tmp_file_name, "w");
        try_times--;
    } while (update_file == NULL && try_times > 0);

    if (update_file == NULL){
        sconf_debug(__func__, "ERROR", "failed to create new config file\n");
        fclose(conf_file);
        return -2;
    }
    
    char buff_init[SCONF_MAX_BUFF], buff_conf[SCONF_MAX_BUFF];
	char character = 0;
	uint16_t idx_char = 0;
	uint16_t idx_conf = 0;
    int8_t conf_cond = 0;
	memset(buff_init, 0x00, SCONF_MAX_BUFF*sizeof(char));
	memset(buff_conf, 0x00, SCONF_MAX_BUFF*sizeof(char));

	while((character = fgetc(conf_file)) != EOF){
		if (character > 127) break;
		if ((character == '\n' || idx_char == SCONF_MAX_BUFF) && conf_cond == 0){
			if(strlen(buff_init) > 0 && strlen(buff_conf) == 0 && idx_conf == 1){
                // do noting
			}
			else if(strncmp(buff_init, "[END]", strlen("[END]")) == 0){
                fprintf(update_file, "[END]\n");
                conf_cond = 1;
				memset(buff_init, 0x00, SCONF_MAX_BUFF*sizeof(char));
				memset(buff_conf, 0x00, SCONF_MAX_BUFF*sizeof(char));
                idx_conf=idx_char=0;
			}
            else {
                fprintf(update_file, "%s%c%s\n", buff_init, SCONF_SEPARATOR, buff_conf);
            }
			memset(buff_init, 0x00, SCONF_MAX_BUFF*sizeof(char));
			memset(buff_conf, 0x00, SCONF_MAX_BUFF*sizeof(char));
			idx_conf=idx_char=0;
		}
		else if(idx_conf==0 && character != SCONF_SEPARATOR && conf_cond == 0){
			buff_init[idx_char] = character;
			idx_char++;
		}
		else if(idx_conf==1 && character != SCONF_SEPARATOR && conf_cond == 0){
			buff_conf[idx_char] = character;
			idx_char++;
		}
		else if(character == SCONF_SEPARATOR && conf_cond == 0){
			idx_char = 0;
			idx_conf = 1;
		}
        else if (conf_cond == 1){
            fprintf(update_file, "%c", character);
        }
	}
	fclose(conf_file);
    fclose(update_file);
    remove(_file_name);
    rename(tmp_file_name, _file_name);
    return 0;
}

int8_t sconf_start_create_new_config(char *_file_name, char *_key, char *_value, ...){
    FILE *conf_file;
    uint8_t try_times = SCONF_OPEN_TRY_TIMES;
    // check existing file
    do{
    	conf_file = fopen(_file_name, "r");
        try_times--;
    } while (conf_file == NULL && try_times > 0);

    if (conf_file != NULL){
        sconf_debug(__func__, "WARNING", "config file was exist. process aborted\n");
        fclose(conf_file);
        return 1;
    }

    // create new file
    try_times = SCONF_OPEN_TRY_TIMES;
    do{
    	conf_file = fopen(_file_name, "w");
        try_times--;
    } while (conf_file == NULL && try_times > 0);

    if (conf_file == NULL){
        sconf_debug(__func__, "ERROR", "failed to create new config file\n");
        return -1;
    }

    va_list aptr;
    char writen_value[SCONF_MAX_BUFF];
    memset (writen_value, 0x00, SCONF_MAX_BUFF*sizeof(char));
	va_start(aptr, _value);
	vsprintf(writen_value, _value, aptr);
	va_end(aptr);

    fprintf(conf_file, "%s%c%s\n", _key, SCONF_SEPARATOR, writen_value);

    fclose(conf_file);
    return 0;
}

int8_t sconf_append_new_config(char *_file_name, char *_key, char *_value, ...){
    FILE *conf_file;
    uint8_t try_times = SCONF_OPEN_TRY_TIMES;
    // check existing file
    do{
    	conf_file = fopen(_file_name, "r");
        try_times--;
    } while (conf_file == NULL && try_times > 0);

    if (conf_file == NULL){
        sconf_debug(__func__, "ERROR", "config doesn't exist\n");
        return -1;
    }

    char character = 0;
    char buff_check[SCONF_MAX_BUFF];
    uint16_t idx_char;
    memset(buff_check, 0x00, SCONF_MAX_BUFF*sizeof(char));

    while((character = fgetc(conf_file)) != EOF){
		if (character > 127) break;
		if (character == '\n' || character == SCONF_SEPARATOR || idx_char == SCONF_MAX_BUFF){
			if(strcmp(buff_check, "[END]") == 0){
                fclose(conf_file);
                sconf_debug(__func__, "WARNING", "this file is finished config. process aborted\n");
                return 1;
			}
            else if(strcmp(buff_check, _key) == 0){
                fclose(conf_file);
                sconf_debug(__func__, "WARNING", "key config \"%s\" already exist. process aborted\n", _key);
                return 1;
			}
			memset(buff_check, 0x00, SCONF_MAX_BUFF*sizeof(char));
            idx_char = 0;
		}
        else{
            buff_check[idx_char] = character;
            idx_char++;
        }
	}

    fclose(conf_file);

    // append data to config
    try_times = SCONF_OPEN_TRY_TIMES;
    do{
    	conf_file = fopen(_file_name, "a");
        try_times--;
    } while (conf_file == NULL && try_times > 0);

    if (conf_file == NULL){
        sconf_debug(__func__, "ERROR", "failed to append new data to config file\n");
        return -2;
    }

    va_list aptr;
    char writen_value[SCONF_MAX_BUFF];
    memset (writen_value, 0x00, SCONF_MAX_BUFF*sizeof(char));
	va_start(aptr, _value);
	vsprintf(writen_value, _value, aptr);
	va_end(aptr);

    if (strlen(writen_value) == 0){
        fprintf(conf_file, "%s\n", _key);
    }
    else{
        fprintf(conf_file, "%s%c%s\n", _key, SCONF_SEPARATOR, writen_value);
    }

    fclose(conf_file);
    return 0;
}

int8_t sconf_end_new_config_file(char *_file_name){
    return sconf_append_new_config(_file_name, "[END]", NULL);
}

int8_t sconf_insert_config(char *_file_name, char *_key, char *_value, ...){
    FILE *conf_file;
    uint8_t try_times = SCONF_OPEN_TRY_TIMES;

    // open existing file
    do{
    	conf_file = fopen(_file_name, "r");
        try_times--;
    } while (conf_file == NULL && try_times > 0);

    if (conf_file == NULL){
        sconf_debug(__func__, "ERROR", "failed to open config file\n");
        return -1;
    }

    // check if key exist
    char character = 0;
    char buff_init[SCONF_MAX_BUFF];
    uint16_t idx_char;

    while((character = fgetc(conf_file)) != EOF){
		if (character > 127) break;
		if (character == '\n' || character == SCONF_SEPARATOR || idx_char == SCONF_MAX_BUFF){
			if(strcmp(buff_init, _key) == 0){
                fclose(conf_file);
                sconf_debug(__func__, "WARNING", "key config \"%s\" already exist. process aborted\n", _key);
                return 1;
			}
            if(strcmp(buff_init, "[END]") == 0){
                break;
			}
			memset(buff_init, 0x00, SCONF_MAX_BUFF*sizeof(char));
            idx_char = 0;
		}
        else{
            buff_init[idx_char] = character;
            idx_char++;
        }
	}

    if(strcmp(buff_init, "[END]") != 0){
        sconf_debug(__func__, "ERROR", "end of config not found. process aborted\n");
        fclose(conf_file);
        return -1;
    }

    fseek(conf_file, 0, SEEK_SET);

    // open new file
    FILE *update_file;
    try_times = SCONF_OPEN_TRY_TIMES;

    char tmp_file_name[strlen(_file_name) + 5];
    memset(tmp_file_name, 0x00, (strlen(_file_name) + 5) *sizeof(char));
    sprintf(tmp_file_name, "%s.tmp", _file_name);

    do{
    	update_file = fopen(tmp_file_name, "w");
        try_times--;
    } while (update_file == NULL && try_times > 0);

    if (update_file == NULL){
        sconf_debug(__func__, "ERROR", "failed to create new config file\n");
        fclose(conf_file);
        return -1;
    }

    va_list aptr;
    char writen_value[SCONF_MAX_BUFF];
    memset (writen_value, 0x00, SCONF_MAX_BUFF*sizeof(char));
	va_start(aptr, _value);
	vsprintf(writen_value, _value, aptr);
	va_end(aptr);

	char buff_conf[SCONF_MAX_BUFF];
	character = 0;
	idx_char = 0;
	uint16_t idx_conf = 0;
    int8_t conf_cond = 0;
	memset(buff_init, 0x00, SCONF_MAX_BUFF*sizeof(char));
	memset(buff_conf, 0x00, SCONF_MAX_BUFF*sizeof(char));
	
	while((character = fgetc(conf_file)) != EOF){
		if (character > 127) break;
		if ((character == '\n' || idx_char == SCONF_MAX_BUFF) && conf_cond == 0){
			if(strncmp(buff_init, "[END]", strlen("[END]")) == 0){
                fprintf(update_file, "%s%c%s\n", _key, SCONF_SEPARATOR, writen_value);
                fprintf(update_file, "[END]\n");
                conf_cond = 1;
				memset(buff_init, 0x00, SCONF_MAX_BUFF*sizeof(char));
				memset(buff_conf, 0x00, SCONF_MAX_BUFF*sizeof(char));
                idx_conf=idx_char=0;
			}
            else {
                fprintf(update_file, "%s%c%s\n", buff_init, SCONF_SEPARATOR, buff_conf);
            }
			memset(buff_init, 0x00, SCONF_MAX_BUFF*sizeof(char));
			memset(buff_conf, 0x00, SCONF_MAX_BUFF*sizeof(char));
			idx_conf=idx_char=0;
		}
		else if(idx_conf==0 && character != SCONF_SEPARATOR && conf_cond == 0){
			buff_init[idx_char] = character;
			idx_char++;
		}
		else if(idx_conf==1 && character != SCONF_SEPARATOR && conf_cond == 0){
			buff_conf[idx_char] = character;
			idx_char++;
		}
		else if(character == SCONF_SEPARATOR && conf_cond == 0){
			idx_char = 0;
			idx_conf = 1;
		}
        else if (conf_cond == 1){
            fprintf(update_file, "%c", character);
        }
	}
	fclose(conf_file);
    fclose(update_file);
    remove(_file_name);
    rename(tmp_file_name, _file_name);
    return 0;
}

int8_t sconf_set_additional_information(char *_file_name, char *_aditional_data){
    FILE *conf_file;
    uint8_t try_times = SCONF_OPEN_TRY_TIMES;
    // check existing file
    do{
    	conf_file = fopen(_file_name, "r");
        try_times--;
    } while (conf_file == NULL && try_times > 0);

    if (conf_file == NULL){
        sconf_debug(__func__, "ERROR", "config doesn't exist\n");
        return -1;
    }

    // check if config file is complete
    char character = 0;
    char buff_init[SCONF_MAX_BUFF];
    uint16_t idx_char;
    memset(buff_init, 0x00, SCONF_MAX_BUFF*sizeof(char));

    while((character = fgetc(conf_file)) != EOF){
		if (character > 127) break;
		if (character == '\n' || character == SCONF_SEPARATOR || idx_char == SCONF_MAX_BUFF){
			if(strcmp(buff_init, "[END]") == 0){
                break;
			}
			memset(buff_init, 0x00, SCONF_MAX_BUFF*sizeof(char));
            idx_char = 0;
		}
        else{
            buff_init[idx_char] = character;
            idx_char++;
        }
	}

    if(strcmp(buff_init, "[END]") != 0){
        sconf_debug(__func__, "ERROR", "end of config not found. process aborted\n");
        fclose(conf_file);
        return -1;
    }

    fseek(conf_file, 0, SEEK_SET);

    // open new file
    FILE *update_file;
    try_times = SCONF_OPEN_TRY_TIMES;

    char tmp_file_name[strlen(_file_name) + 5];
    memset(tmp_file_name, 0x00, (strlen(_file_name) + 5) *sizeof(char));
    sprintf(tmp_file_name, "%s.tmp", _file_name);

    do{
    	update_file = fopen(tmp_file_name, "w");
        try_times--;
    } while (update_file == NULL && try_times > 0);

    if (update_file == NULL){
        sconf_debug(__func__, "ERROR", "failed to create new config file\n");
        fclose(conf_file);
        return -1;
    }

	char buff_conf[SCONF_MAX_BUFF];
	character = 0;
	idx_char = 0;
	uint16_t idx_conf = 0;
	memset(buff_init, 0x00, SCONF_MAX_BUFF*sizeof(char));
	memset(buff_conf, 0x00, SCONF_MAX_BUFF*sizeof(char));
	
	while((character = fgetc(conf_file)) != EOF){
		if (character > 127) break;
		if (character == '\n' || idx_char == SCONF_MAX_BUFF){
			if(strncmp(buff_init, "[END]", strlen("[END]")) == 0){
                fprintf(update_file, "[END]\n");
                fprintf(update_file, "%s", _aditional_data);
				memset(buff_init, 0x00, SCONF_MAX_BUFF*sizeof(char));
				memset(buff_conf, 0x00, SCONF_MAX_BUFF*sizeof(char));
                idx_conf=idx_char=0;
                break;
			}
            else {
                fprintf(update_file, "%s%c%s\n", buff_init, SCONF_SEPARATOR, buff_conf);
            }
			memset(buff_init, 0x00, SCONF_MAX_BUFF*sizeof(char));
			memset(buff_conf, 0x00, SCONF_MAX_BUFF*sizeof(char));
			idx_conf=idx_char=0;
		}
		else if(idx_conf==0 && character != SCONF_SEPARATOR){
			buff_init[idx_char] = character;
			idx_char++;
		}
		else if(idx_conf==1 && character != SCONF_SEPARATOR){
			buff_conf[idx_char] = character;
			idx_char++;
		}
		else if(character == SCONF_SEPARATOR){
			idx_char = 0;
			idx_conf = 1;
		}
	}
	fclose(conf_file);
    fclose(update_file);
    remove(_file_name);
    rename(tmp_file_name, _file_name);
    return 0;
}

int8_t sconf_append_additional_information(char *_file_name, char *_aditional_data){
    FILE *conf_file;
    uint8_t try_times = SCONF_OPEN_TRY_TIMES;
    // check existing file
    do{
    	conf_file = fopen(_file_name, "r");
        try_times--;
    } while (conf_file == NULL && try_times > 0);

    if (conf_file == NULL){
        sconf_debug(__func__, "ERROR", "config doesn't exist\n");
        return -1;
    }

    // check if config file is complete
    char character = 0;
    char buff_init[SCONF_MAX_BUFF];
    uint16_t idx_char;
    memset(buff_init, 0x00, SCONF_MAX_BUFF*sizeof(char));

    while((character = fgetc(conf_file)) != EOF){
		if (character > 127) break;
		if (character == '\n' || character == SCONF_SEPARATOR || idx_char == SCONF_MAX_BUFF){
			if(strcmp(buff_init, "[END]") == 0){
                break;
			}
			memset(buff_init, 0x00, SCONF_MAX_BUFF*sizeof(char));
            idx_char = 0;
		}
        else{
            buff_init[idx_char] = character;
            idx_char++;
        }
	}

    fclose(conf_file);

    if(strcmp(buff_init, "[END]") != 0){
        sconf_debug(__func__, "ERROR", "end of config not found. process aborted\n");
        return -1;
    }

    // append data to config
    try_times = SCONF_OPEN_TRY_TIMES;
    do{
    	conf_file = fopen(_file_name, "a");
        try_times--;
    } while (conf_file == NULL && try_times > 0);

    if (conf_file == NULL){
        sconf_debug(__func__, "ERROR", "failed to append additional information\n");
        return -2;
    }

    fprintf(conf_file, "%s", _aditional_data);

    fclose(conf_file);
    return 0;
}

int8_t sconf_get_additional_information(char *_file_name, char *_aditional_data, uint16_t _max_data_to_get){
    FILE *conf_file;
    uint8_t try_times = SCONF_OPEN_TRY_TIMES;

    do{
    	conf_file = fopen(_file_name, "r");
        try_times--;
    } while (conf_file == NULL && try_times > 0);

    if (conf_file == NULL){
        sconf_debug(__func__, "ERROR", "failed to open config file\n");
        return -1;
    }

	char buff_check[SCONF_MAX_BUFF];
    char value_return[_max_data_to_get + 1];
	char character = 0;
	uint16_t idx_char = 0;
	uint16_t conf_cond = 0;
    uint16_t additional_idx_chr = 0;
	memset(buff_check, 0x00, SCONF_MAX_BUFF*sizeof(char));
    memset (value_return, 0x00, (_max_data_to_get + 1)*sizeof(char));
	
	while((character = fgetc(conf_file)) != EOF){
		if (character > 127 || additional_idx_chr == _max_data_to_get) break;
		if ((character == '\n' || character == SCONF_SEPARATOR || idx_char == SCONF_MAX_BUFF) && conf_cond == 0){
			if(strcmp(buff_check, "[END]") == 0){
				conf_cond = 1;
			}
			memset(buff_check, 0x00, SCONF_MAX_BUFF*sizeof(char));
            idx_char=0;
		}
		else if(conf_cond==0){
			buff_check[idx_char] = character;
			idx_char++;
		}
        else if(conf_cond==1){
            value_return[additional_idx_chr] = character;
            additional_idx_chr++;
        }
	}
	fclose(conf_file);
    if (additional_idx_chr > 0){
        strcpy(_aditional_data, value_return);
        return 0;
    }
    return 1;
}

int8_t sconf_disable_config(char *_file_name, char *_key){
    char key_tmp[strlen(_key) + 2];
    memset(key_tmp, 0x00, (strlen(_key) + 2) * sizeof(char));
    key_tmp[0] = SCONF_DISABLE_FLAG;
    strcat(key_tmp, _key);
    return sconf_update_keyword(_file_name, _key, key_tmp);
}

int8_t sconf_enable_config(char *_file_name, char *_key){
    char key_tmp[strlen(_key) + 2];
    memset(key_tmp, 0x00, (strlen(_key) + 2) * sizeof(char));
    key_tmp[0] = SCONF_DISABLE_FLAG;
    strcat(key_tmp, _key);
    return sconf_update_keyword(_file_name, key_tmp, _key);
}

// ADDITIONAL FUNCTION LINE_CONFIG

int8_t sconf_check_config_by_line(char *_file_name, char *_line_value){
    FILE *conf_file;
    uint8_t try_times = SCONF_OPEN_TRY_TIMES;

    do{
    	conf_file = fopen(_file_name, "r");
        try_times--;
    } while (conf_file == NULL && try_times > 0);

    if (conf_file == NULL){
        sconf_debug(__func__, "ERROR", "failed to open config file\n");
        return -1;
    }

	char buff[SCONF_MAX_LINE_LENGTH];
	char character = 0;
	uint16_t idx_char = 0;
	uint16_t idx_conf = 0;
	memset(buff, 0x00, SCONF_MAX_LINE_LENGTH*sizeof(char));
	
	while((character = fgetc(conf_file)) != EOF){
		if (character > 127) break;
		if (character == '\n' || idx_char == SCONF_MAX_LINE_LENGTH){
			if(strcmp(buff, _line_value) == 0){
				idx_conf++;
			}
			memset(buff, 0x00, SCONF_MAX_LINE_LENGTH*sizeof(char));
			idx_char=0;
		}
		else if(SCONF_SKIP_SPACE_FROM_LINE == SCONF_CHECK_WITH_SPACE){
			buff[idx_char] = character;
			idx_char++;
		}
        else if(SCONF_SKIP_SPACE_FROM_LINE == SCONF_CHECK_WITHOUT_SPACE){
            if (character != ' '){
                buff[idx_char] = character;
			    idx_char++;
            }
        }
	}
	fclose(conf_file);
    return idx_conf;
}

int8_t sconf_disable_config_by_line(char *_file_name, char *_line_value){
    if (_line_value[0] == SCONF_DISABLE_FLAG){
        sconf_debug(__func__, "ERROR", "put line value without '%c' flag\n", SCONF_DISABLE_FLAG);
        return -1;
    }
    int8_t setup_tmp = SCONF_SKIP_SPACE_FROM_LINE;
    SCONF_SKIP_SPACE_FROM_LINE = SCONF_CHECK_WITH_SPACE;
    if (sconf_check_config_by_line(_file_name, _line_value) <= 0){
        char line_value_tmp[strlen(_line_value) + 2];
        memset(line_value_tmp, 0x00, (strlen(_line_value) + 2) * sizeof(char));
        sprintf(line_value_tmp, "%c%s", SCONF_DISABLE_FLAG, _line_value);
        if (sconf_check_config_by_line(_file_name, line_value_tmp) <= 0){
            sconf_debug(__func__, "WARNING", "matching line config not found\n");
        }
        else {
            sconf_debug(__func__, "WARNING", "matching line config has been disabled\n");
        }
        SCONF_SKIP_SPACE_FROM_LINE = setup_tmp;
        return -1;
    }
    SCONF_SKIP_SPACE_FROM_LINE = setup_tmp;
    
    FILE *conf_file;
    uint8_t try_times = SCONF_OPEN_TRY_TIMES;

    do{
    	conf_file = fopen(_file_name, "r");
        try_times--;
    } while (conf_file == NULL && try_times > 0);

    if (conf_file == NULL){
        sconf_debug(__func__, "ERROR", "failed to open config file\n");
        return -1;
    }

    // open new file
    char tmp_file_name[strlen(_file_name) + 5];
    memset(tmp_file_name, 0x00, (strlen(_file_name) + 5) *sizeof(char));
    sprintf(tmp_file_name, "%s.tmp", _file_name);
    FILE *update_file;
    try_times = SCONF_OPEN_TRY_TIMES;

    do{
    	update_file = fopen(tmp_file_name, "w");
        try_times--;
    } while (update_file == NULL && try_times > 0);

    if (update_file == NULL){
        sconf_debug(__func__, "ERROR", "failed to create new file\n");
        fclose(conf_file);
        return -1;
    }

	char buff[SCONF_MAX_LINE_LENGTH];
	char character = 0;
	uint16_t idx_char = 0;
	memset(buff, 0x00, SCONF_MAX_LINE_LENGTH*sizeof(char));
	
	while((character = fgetc(conf_file)) != EOF){
		if (character > 127) break;
		if (character == '\n' || idx_char == SCONF_MAX_LINE_LENGTH){
			if(strcmp(buff, _line_value) == 0){
                fprintf(update_file, "%c", SCONF_DISABLE_FLAG);
                fprintf(update_file, "%s\n", buff);
			}
            else {
                if (character == '\n'){
                    fprintf(update_file, "%s\n", buff);
                }
                else {
                    fprintf(update_file, "%s", buff);
                }
            }
			memset(buff, 0x00, SCONF_MAX_LINE_LENGTH*sizeof(char));
			idx_char=0;
		}
		else if(SCONF_SKIP_SPACE_FROM_LINE == SCONF_CHECK_WITH_SPACE){
			buff[idx_char] = character;
			idx_char++;
		}
        else if(SCONF_SKIP_SPACE_FROM_LINE == SCONF_CHECK_WITHOUT_SPACE){
            if (character != ' '){
                buff[idx_char] = character;
			    idx_char++;
            }
        }
	}
	fclose(conf_file);
    fclose(update_file);
    remove(_file_name);
    rename(tmp_file_name, _file_name);
    return 0;
}

int8_t sconf_enable_config_by_line(char *_file_name, char *_line_value){
    if (_line_value[0] == SCONF_DISABLE_FLAG){
        sconf_debug(__func__, "ERROR", "put line value without '%c' flag\n", SCONF_DISABLE_FLAG);
        return -1;
    }
    int8_t setup_tmp = SCONF_SKIP_SPACE_FROM_LINE;
    SCONF_SKIP_SPACE_FROM_LINE = SCONF_CHECK_WITH_SPACE;
    char line_value_tmp[strlen(_line_value) + 2];
    memset(line_value_tmp, 0x00, (strlen(_line_value) + 2) * sizeof(char));
    sprintf(line_value_tmp, "%c%s", SCONF_DISABLE_FLAG, _line_value);
    if (sconf_check_config_by_line(_file_name, line_value_tmp) <= 0){
        if (sconf_check_config_by_line(_file_name, _line_value) <= 0){
            sconf_debug(__func__, "WARNING", "matching line config not found\n");
        }
        else {
            sconf_debug(__func__, "WARNING", "matching line config has been enabled\n");
        }
        SCONF_SKIP_SPACE_FROM_LINE = setup_tmp;
        return -1;
    }
    SCONF_SKIP_SPACE_FROM_LINE = setup_tmp;
    
    FILE *conf_file;
    uint8_t try_times = SCONF_OPEN_TRY_TIMES;

    do{
    	conf_file = fopen(_file_name, "r");
        try_times--;
    } while (conf_file == NULL && try_times > 0);

    if (conf_file == NULL){
        sconf_debug(__func__, "ERROR", "failed to open config file\n");
        return -1;
    }

    // open new file
    char tmp_file_name[strlen(_file_name) + 5];
    memset(tmp_file_name, 0x00, (strlen(_file_name) + 5) *sizeof(char));
    sprintf(tmp_file_name, "%s.tmp", _file_name);
    FILE *update_file;
    try_times = SCONF_OPEN_TRY_TIMES;

    do{
    	update_file = fopen(tmp_file_name, "w");
        try_times--;
    } while (update_file == NULL && try_times > 0);

    if (update_file == NULL){
        sconf_debug(__func__, "ERROR", "failed to create new file\n");
        fclose(conf_file);
        return -1;
    }

	char buff[SCONF_MAX_LINE_LENGTH];
	char character = 0;
	uint16_t idx_char = 0;
	memset(buff, 0x00, SCONF_MAX_LINE_LENGTH*sizeof(char));
	
	while((character = fgetc(conf_file)) != EOF){
		if (character > 127) break;
		if (character == '\n' || idx_char == SCONF_MAX_LINE_LENGTH){
			if(strcmp(buff, line_value_tmp) == 0){
                fprintf(update_file, "%s\n", _line_value);
			}
            else {
                if (character == '\n'){
                    fprintf(update_file, "%s\n", buff);
                }
                else {
                    fprintf(update_file, "%s", buff);
                }
            }
			memset(buff, 0x00, SCONF_MAX_LINE_LENGTH*sizeof(char));
			idx_char=0;
		}
		else if(SCONF_SKIP_SPACE_FROM_LINE == SCONF_CHECK_WITH_SPACE){
			buff[idx_char] = character;
			idx_char++;
		}
        else if(SCONF_SKIP_SPACE_FROM_LINE == SCONF_CHECK_WITHOUT_SPACE){
            if (character != ' '){
                buff[idx_char] = character;
			    idx_char++;
            }
        }
	}
	fclose(conf_file);
    fclose(update_file);
    remove(_file_name);
    rename(tmp_file_name, _file_name);
    return 0;
}

int8_t sconf_append_line_config(char *_file_name, char *_line_value){
    if (_line_value[0] == SCONF_DISABLE_FLAG){
        sconf_debug(__func__, "ERROR", "put line value without '%c' flag\n", SCONF_DISABLE_FLAG);
        return -1;
    }
    int8_t setup_tmp = SCONF_SKIP_SPACE_FROM_LINE;
    SCONF_SKIP_SPACE_FROM_LINE = SCONF_CHECK_WITH_SPACE;
    if (sconf_check_config_by_line(_file_name, _line_value) > 0){
        sconf_debug(__func__, "WARNING", "matching line config found. process aborted\n");
        SCONF_SKIP_SPACE_FROM_LINE = setup_tmp;
        return -1;
    }
    
    char line_value_tmp[strlen(_line_value) + 2];
    memset(line_value_tmp, 0x00, (strlen(_line_value) + 2) * sizeof(char));
    sprintf(line_value_tmp, "%c%s", SCONF_DISABLE_FLAG, _line_value);
    if (sconf_check_config_by_line(_file_name, line_value_tmp) > 0){
        sconf_debug(__func__, "INFO", "matching line config found as disable config. switch to enabling process\n");
        if (sconf_enable_config_by_line(_file_name, _line_value) == 0){
            sconf_debug(__func__, "INFO", "success to execute process\n");
            SCONF_SKIP_SPACE_FROM_LINE = setup_tmp;
            return 0;
        }
        else {
            sconf_debug(__func__, "ERROR", "failed to execute process\n");
            SCONF_SKIP_SPACE_FROM_LINE = setup_tmp;
            return -1;
        }
    }

    SCONF_SKIP_SPACE_FROM_LINE = setup_tmp;
    
    FILE *conf_file;
    uint8_t try_times = SCONF_OPEN_TRY_TIMES;

    do{
    	conf_file = fopen(_file_name, "a");
        try_times--;
    } while (conf_file == NULL && try_times > 0);

    if (conf_file == NULL){
        sconf_debug(__func__, "ERROR", "failed to open config file\n");
        return -1;
    }

    fprintf(conf_file, "%s", _line_value);

    fclose(conf_file);

    return 0;
}