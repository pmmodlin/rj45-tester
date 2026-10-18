#include "rj45_tester.h"

#include <furi_hal.h>

#define SETTINGS_MAGIC   0x34354A52 /* "RJ45" */
#define SETTINGS_VERSION 1

void settings_device_mac(uint8_t mac[6]) {
    /* Stable per Flipper: derived from the MCU UID, locally administered */
    const uint8_t* uid = furi_hal_version_uid();
    size_t n = furi_hal_version_uid_size();
    uint8_t h[6] = {0x02, 0x46, 0x5A, 0, 0, 0}; /* 02:46:5A = "FZ" */
    for(size_t i = 0; i < n; i++) h[3 + (i % 3)] ^= uid[i];
    memcpy(mac, h, 6);
}

void settings_defaults(Settings* s) {
    memset(s, 0, sizeof(*s));
    s->magic = SETTINGS_MAGIC;
    s->version = SETTINGS_VERSION;
    s->dhcp = true;
    memcpy(s->ip, (const uint8_t[]){192, 168, 1, 250}, 4);
    memcpy(s->mask, (const uint8_t[]){255, 255, 255, 0}, 4);
    memcpy(s->gw, (const uint8_t[]){192, 168, 1, 1}, 4);
    memcpy(s->dns, (const uint8_t[]){192, 168, 1, 1}, 4);
    s->phy_mode = PhyAuto;
    s->mac_mode = MacFromDevice;
    settings_device_mac(s->custom_mac);
    s->sound = true;
    s->vibro = true;
    s->otg = false;
    s->log_sd = true;
    s->ping_preset = 0;
    memcpy(s->ping_custom, (const uint8_t[]){192, 168, 1, 1}, 4);
    strlcpy(s->dns_name, "google.com", sizeof(s->dns_name));
}

void settings_load(App* app) {
    settings_defaults(&app->settings);
    storage_simply_mkdir(app->storage, APP_DIR);
    File* f = storage_file_alloc(app->storage);
    Settings tmp;
    if(storage_file_open(f, SETTINGS_PATH, FSAM_READ, FSOM_OPEN_EXISTING) &&
       storage_file_read(f, &tmp, sizeof(tmp)) == sizeof(tmp) && tmp.magic == SETTINGS_MAGIC &&
       tmp.version == SETTINGS_VERSION) {
        tmp.dns_name[sizeof(tmp.dns_name) - 1] = 0;
        if(tmp.phy_mode >= PhyModeCount) tmp.phy_mode = PhyAuto;
        if(tmp.ping_preset >= PING_PRESETS) tmp.ping_preset = 0;
        app->settings = tmp;
    }
    storage_file_close(f);
    storage_file_free(f);
}

void settings_save(App* app) {
    storage_simply_mkdir(app->storage, APP_DIR);
    File* f = storage_file_alloc(app->storage);
    if(storage_file_open(f, SETTINGS_PATH, FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
        storage_file_write(f, &app->settings, sizeof(app->settings));
    }
    storage_file_close(f);
    storage_file_free(f);
}
