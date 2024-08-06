//
// Created by chomnr on 7/22/24. for Brute.
//

#include "library.h"
#include <stdio.h>
#include <stdlib.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <curl/curl.h>

#define BE_LOG_FILE "/var/log/brute_log.txt"
#define BRUTE_BEARER_TOKEN "{TOKEN}"
#define BRUTE_POST_URL "http://127.0.0.1:3000/brute/attack/add"

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    char *username, *password, *protocol, *ip_address;

    // Retrieve user information
    pam_get_item(pamh, PAM_USER, (void*)&username);
    pam_get_item(pamh, PAM_AUTHTOK, (void*)&password);
    pam_get_item(pamh, PAM_RHOST, (void*)&ip_address);
    pam_get_item(pamh, PAM_SERVICE, (void*)&protocol);

    // log any errors.
    FILE *log_file = fopen(BE_LOG_FILE, "a");
    if (log_file == NULL) {
        fprintf(stderr, "Failed to open log file %s\n", BE_LOG_FILE);
        return PAM_SUCCESS;
    }

    // Payload that is going to be sent
    char json_payload[1024];
    snprintf(json_payload, sizeof(json_payload),
             "{\"username\":\"%s\",\"password\":\"%s\",\"protocol\":\"%s\",\"ip_address\":\"%s\"}",
             username, password, protocol, ip_address);

    // Initialize libcurl
    CURL *curl;
    CURLcode result;

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    if (curl) {
        // Set URL and payload for HTTP POST request
        curl_easy_setopt(curl, CURLOPT_URL, BRUTE_POST_URL);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_payload);

        // Set headers for JSON content type and authorization
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        char auth_header[256];
        snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s", BRUTE_BEARER_TOKEN);
        headers = curl_slist_append(headers, auth_header);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        // Perform HTTP POST request
        result = curl_easy_perform(curl);
        if (result != CURLE_OK) {
            fprintf(log_file, "curl_easy_perform() failed: %s\n", curl_easy_strerror(result));
        }

        // Cleanup
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    } else {
        fprintf(log_file, "Failed to initialize curl.\n");
    }

    // Cleanup libcurl
    curl_global_cleanup();

    // Close log file
    fclose(log_file);

    return PAM_SUCCESS;
}