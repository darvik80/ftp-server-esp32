//
// Created by darvik on 29.12.2024.
//

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

void oss_utils_trim_whitespace(char** str);

char *oss_utils_assign_string(char **str, const char *new_str, int len);

char *oss_utils_append_string(char **str, const char *new_str, int len);

#ifdef __cplusplus
}
#endif