//
// Created by darvik on 29.12.2024.
//

#include <ctype.h>
#include <string.h>


#ifndef mem_check
#define mem_check(x) assert(x)
#endif

void oss_utils_trim_whitespace(char** str)
{
    char *end, *start;
    if (str == NULL)
    {
        return;
    }
    start = *str;
    if (start == NULL)
    {
        return;
    }
    // Trim leading space
    while (isspace((unsigned char)*start)) start++;

    if (*start == 0)
    {
        // All spaces?
        **str = 0;
        return;
    }

    // Trim trailing space
    end = (char*)(start + strlen(start) - 1);
    while (end > start && isspace((unsigned char)*end))
    {
        end--;
    }

    // Write new null terminator
    *(end + 1) = 0;
    memmove(*str, start, strlen(start) + 1);
}

char *oss_utils_assign_string(char **str, const char *new_str, int len)
{
    int l = len;
    if (new_str == NULL) {
        return NULL;
    }
    char *old_str = *str;
    if (l < 0) {
        l = strlen(new_str);
    }
    if (old_str) {
        old_str = realloc(old_str, l + 1);
        mem_check(old_str);
        old_str[l] = 0;
    } else {
        old_str = calloc(1, l + 1);
        mem_check(old_str);
    }
    memcpy(old_str, new_str, l);
    *str = old_str;
    return old_str;
}

char *oss_utils_append_string(char **str, const char *new_str, int len)
{
    int l = len;
    int old_len = 0;
    char *old_str = *str;
    if (new_str != NULL) {
        if (l < 0) {
            l = strlen(new_str);
        }
        if (old_str) {
            old_len = strlen(old_str);
            old_str = realloc(old_str, old_len + l + 1);
            mem_check(old_str);
            old_str[old_len + l] = 0;
        } else {
            old_str = calloc(1, l + 1);
            mem_check(old_str);
        }
        memcpy(old_str + old_len, new_str, l);
        *str = old_str;
    }
    return old_str;
}
