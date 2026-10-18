#pragma once

#include <furi.h>
#include <gui/gui.h>
#include <gui/view_dispatcher.h>
#include <gui/modules/submenu.h>
#include <gui/modules/variable_item_list.h>
#include <gui/modules/byte_input.h>
#include <gui/modules/text_input.h>
#include <notification/notification.h>
#include <storage/storage.h>

#define APP_DIR       EXT_PATH("apps_data/rj45_tester")
#define SETTINGS_PATH APP_DIR "/settings.bin"
#define LOG_PATH      APP_DIR "/log.txt"

#define LOG_LINES   120
#define LOG_LEN     44
#define ARP_MAX     64
#define DHCPSRV_MAX 6
#define VLAN_MAX    8
#define STR_SHORT   32

#define IPF       "%u.%u.%u.%u"
#define IPA(a)    (a)[0], (a)[1], (a)[2], (a)[3]
#define MACF      "%02X:%02X:%02X:%02X:%02X:%02X"
#define MACA(m)   (m)[0], (m)[1], (m)[2], (m)[3], (m)[4], (m)[5]
#define IP_ZERO(a) (!((a)[0] | (a)[1] | (a)[2] | (a)[3]))

typedef enum {
    PhyAuto,
    Phy100Full,
    Phy100Half,
    Phy10Full,
    Phy10Half,
    PhyModeCount,
} PhyModeSetting;

typedef enum {
    MacFromDevice,
    MacRandom,
    MacCustom,
} MacSetting;

typedef struct {
    uint32_t magic;
    uint8_t version;
    bool dhcp;
    uint8_t ip[4];
    uint8_t mask[4];
    uint8_t gw[4];
    uint8_t dns[4];
    uint8_t phy_mode;
    uint8_t mac_mode;
    uint8_t custom_mac[6];
    bool sound;
    bool vibro;
    bool otg;
    bool log_sd;
    uint8_t ping_preset;
    uint8_t ping_custom[4];
    char dns_name[64];
    uint8_t wol_mac[6];
} Settings;

typedef struct {
    uint8_t ip[4];
    uint8_t mac[6];
} ArpHost;

typedef struct {
    uint8_t server[4]; /* server identifier option */
    uint8_t offered[4];
    uint8_t router[4];
    uint32_t lease;
} DhcpServer;

typedef struct {
    bool valid;
    char proto[5]; /* LLDP / CDP */
    char sys_name[STR_SHORT];
    char port_id[STR_SHORT];
    char port_desc[STR_SHORT];
    char platform[STR_SHORT];
    uint8_t mgmt_ip[4];
    bool has_mgmt;
    uint16_t vlan;
    uint16_t voice_vlan;
    char duplex[12]; /* what the switch reports for its side */
    char poe[24];
    uint32_t seen_tick;
    uint16_t ttl;
} Neighbor;

typedef struct {
    bool valid;
    bool rstp;
    uint16_t root_prio;
    uint8_t root_mac[6];
    uint32_t root_cost;
    uint16_t bridge_prio;
    uint8_t bridge_mac[6];
    uint32_t seen_tick;
} StpInfo;

typedef struct {
    /* chip and link */
    bool chip_ok;
    uint8_t phy;
    bool link;
    uint32_t link_change_tick;
    uint32_t link_ups;
    uint32_t link_downs;
    uint32_t down_ms_total;
    uint32_t last_down_ms;
    uint32_t session_tick;

    /* IP */
    bool have_ip;
    bool dhcp_busy;
    uint8_t ip[4];
    uint8_t mask[4];
    uint8_t gw[4];
    uint8_t dns[4];
    uint8_t dhcp_server[4];
    uint32_t lease;
    uint32_t lease_tick;
    uint32_t dhcp_ms;
    uint8_t mac[6];
    uint32_t conflicts;

    /* frames seen by the MACRAW socket */
    uint32_t rx_frames;
    uint32_t rx_bytes;
    uint32_t rx_bcast;
    uint32_t rx_mcast;
    uint32_t rx_arp;
    uint32_t rx_ipv4;
    uint32_t rx_ipv6;
    uint32_t rx_other;
    uint32_t rx_tagged;
    uint32_t pps;
    uint32_t bcast_pps;
    uint32_t pps_peak;
    uint16_t vlans[VLAN_MAX];
    uint8_t vlan_count;

    Neighbor neighbor;
    StpInfo stp;

    /* ping */
    bool ping_running;
    uint8_t ping_ip[4];
    uint32_t ping_sent;
    uint32_t ping_recv;
    uint32_t ping_last;
    uint32_t ping_min;
    uint32_t ping_max;
    uint32_t ping_sum;
    uint8_t ping_hist[32]; /* last results, rtt clamped to 254, 255 = lost */
    uint8_t ping_hist_len;
    char ping_status[STR_SHORT];

    /* dns */
    bool dns_busy;
    bool dns_ok;
    uint8_t dns_result[4];
    uint32_t dns_ms;
    char dns_status[STR_SHORT];

    /* arp scan */
    bool arp_busy;
    uint16_t arp_done;
    uint16_t arp_total;
    ArpHost arp[ARP_MAX];
    uint8_t arp_count;

    /* dhcp servers */
    bool dhcps_busy;
    bool dhcps_done;
    DhcpServer dhcps[DHCPSRV_MAX];
    uint8_t dhcps_count;

    /* wol */
    char wol_status[STR_SHORT];

    /* log */
    char log[LOG_LINES][LOG_LEN];
    uint16_t log_head;
    uint16_t log_count;
} NetState;

typedef enum {
    ScreenStatus,
    ScreenNeighbors,
    ScreenPing,
    ScreenDns,
    ScreenArp,
    ScreenDhcp,
    ScreenTraffic,
    ScreenLog,
    ScreenWol,
    ScreenAbout,
} Screen;

typedef enum {
    ViewMenu,
    ViewScreen,
    ViewSettings,
    ViewByteInput,
    ViewTextInput,
} ViewId;

/* worker flags */
#define WF_EXIT      (1 << 0)
#define WF_APPLY     (1 << 1)
#define WF_DHCP      (1 << 2)
#define WF_PING      (1 << 3)
#define WF_DNS       (1 << 4)
#define WF_ARP       (1 << 5)
#define WF_DHCPSCAN  (1 << 6)
#define WF_WOL       (1 << 7)
#define WF_CLEAR     (1 << 8)
#define WF_PING_STOP (1 << 9)
#define WF_ALL       0x3FF

typedef struct App App;

typedef struct {
    App* app;
} ScreenModel;

struct App {
    Gui* gui;
    ViewDispatcher* view_dispatcher;
    Submenu* menu;
    View* screen_view;
    VariableItemList* settings_list;
    ByteInput* byte_input;
    TextInput* text_input;
    NotificationApp* notifications;
    Storage* storage;
    FuriTimer* redraw_timer;
    FuriThread* worker;
    FuriMutex* mutex;

    Settings settings;
    NetState st;

    Screen screen;
    int16_t scroll;
    uint8_t edit_buf[6];
    uint8_t* edit_target;
    uint8_t edit_len;
    ViewId edit_return;
    ViewId current;
    bool settings_dirty;
    char text_buf[64];
    bool otg_enabled_by_us;
};

/* worker.c */
int32_t worker_thread(void* ctx);
void worker_signal(App* app, uint32_t flags);
void app_log(App* app, const char* fmt, ...) _ATTRIBUTE((__format__(__printf__, 2, 3)));
void ping_target_resolve(App* app, uint8_t out[4]);

/* settings.c */
void settings_defaults(Settings* s);
void settings_load(App* app);
void settings_save(App* app);
void settings_device_mac(uint8_t mac[6]);

/* screens.c */
void screen_draw(Canvas* canvas, void* model);
bool screen_input(InputEvent* event, void* ctx);
void settings_view_rebuild(App* app);

extern const char* const ping_preset_names[];
#define PING_PRESETS 5
