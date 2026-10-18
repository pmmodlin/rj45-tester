#include "rj45_tester.h"
#include "w5500.h"

#include <furi_hal.h>
#include <notification/notification_messages.h>
#include <stdarg.h>

#define S_RAW  0
#define S_DHCP 1
#define S_DNS  2
#define S_ICMP 3
#define S_ARP0 4
#define S_ARPN 4

#define DHCP_DISCOVER 1
#define DHCP_OFFER    2
#define DHCP_REQUEST  3
#define DHCP_ACK      5
#define DHCP_NAK      6

#define FRAME_MAX 600

typedef struct {
    App* app;
    uint32_t phy_tick;
    uint32_t ver_tick;
    uint32_t sec_tick;
    uint32_t frames_sec;
    uint32_t bcast_sec;
    uint32_t chip_tick;
    bool chip_missing_logged;
    bool dhcp_pending;
    bool was_down;
    bool storm;
    bool dhcp_renew;
    uint32_t dhcp_retry_tick;
    uint32_t ping_tick;
    uint16_t ping_seq;
    uint16_t ping_id;
    uint8_t frame[FRAME_MAX];
    uint8_t pkt[600];
} Worker;

static const uint8_t ip_bcast[4] = {255, 255, 255, 255};
static const uint8_t ip_zero[4] = {0, 0, 0, 0};

#define LOCK(app)   furi_mutex_acquire((app)->mutex, FuriWaitForever)
#define UNLOCK(app) furi_mutex_release((app)->mutex)

/* ---------- log ---------- */

void app_log(App* app, const char* fmt, ...) {
    char msg[LOG_LEN];
    DateTime dt;
    furi_hal_rtc_get_datetime(&dt);
    int n = snprintf(msg, sizeof(msg), "%02u:%02u:%02u ", dt.hour, dt.minute, dt.second);
    va_list args;
    va_start(args, fmt);
    vsnprintf(msg + n, sizeof(msg) - n, fmt, args);
    va_end(args);

    LOCK(app);
    NetState* st = &app->st;
    strlcpy(st->log[st->log_head], msg, LOG_LEN);
    st->log_head = (st->log_head + 1) % LOG_LINES;
    if(st->log_count < LOG_LINES) st->log_count++;
    bool to_sd = app->settings.log_sd;
    UNLOCK(app);

    if(to_sd) {
        File* f = storage_file_alloc(app->storage);
        if(storage_file_open(f, LOG_PATH, FSAM_WRITE, FSOM_OPEN_APPEND)) {
            char line[LOG_LEN + 16];
            /* the message already starts with the time */
            int len =
                snprintf(line, sizeof(line), "%04u-%02u-%02u %s\n", dt.year, dt.month, dt.day, msg);
            storage_file_write(f, line, len);
        }
        storage_file_close(f);
        storage_file_free(f);
    }
}

void worker_signal(App* app, uint32_t flags) {
    furi_thread_flags_set(furi_thread_get_id(app->worker), flags);
}

/* ---------- notifications ---------- */

static const NotificationSequence seq_up_sound = {
    &message_note_c6,
    &message_delay_100,
    &message_note_e6,
    &message_delay_100,
    &message_sound_off,
    NULL,
};

static const NotificationSequence seq_down_sound = {
    &message_note_e5,
    &message_delay_100,
    &message_note_c5,
    &message_delay_250,
    &message_sound_off,
    NULL,
};

static void notify_link(App* app, bool up) {
    notification_message(app->notifications, up ? &sequence_blink_green_100 : &sequence_blink_red_100);
    if(app->settings.vibro) {
        notification_message(app->notifications, up ? &sequence_single_vibro : &sequence_double_vibro);
    }
    if(app->settings.sound) {
        notification_message(app->notifications, up ? &seq_up_sound : &seq_down_sound);
    }
}

/* ---------- helpers ---------- */

static uint16_t rd16(const uint8_t* p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}

static uint32_t rd32(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static void copy_str(char* dst, size_t size, const uint8_t* src, size_t len) {
    size_t j = 0;
    for(size_t i = 0; i < len && j + 1 < size; i++) {
        char c = (char)src[i];
        if(c == '\r' || c == '\n') c = ' ';
        if(c >= 32 && c < 127) dst[j++] = c;
    }
    dst[j] = 0;
}

static void mac_str(char* dst, size_t size, const uint8_t* m) {
    snprintf(dst, size, MACF, MACA(m));
}

static const char* phy_mode_name(uint8_t m) {
    static const char* const names[] = {"auto", "100 FD", "100 HD", "10 FD", "10 HD"};
    return m < PhyModeCount ? names[m] : "?";
}

static void ping_hist_push(NetState* st, uint8_t v) {
    if(st->ping_hist_len < sizeof(st->ping_hist)) {
        st->ping_hist[st->ping_hist_len++] = v;
    } else {
        memmove(st->ping_hist, st->ping_hist + 1, sizeof(st->ping_hist) - 1);
        st->ping_hist[sizeof(st->ping_hist) - 1] = v;
    }
}

static bool abort_requested(Worker* w) {
    uint32_t f = furi_thread_flags_get();
    return (f & (WF_EXIT | WF_APPLY)) || !w->app->st.link || !w->app->st.chip_ok;
}

static void worker_poll(Worker* w);

/* Wait while keeping the link monitor and sniffer running.
 * Returns false when the wait was interrupted (exit, settings, link lost). */
static bool wait_ms(Worker* w, uint32_t ms) {
    uint32_t start = furi_get_tick();
    do {
        worker_poll(w);
        if(abort_requested(w)) return false;
        furi_delay_ms(2);
    } while(furi_get_tick() - start < ms);
    return true;
}

/* ---------- frame sniffer (socket 0, MACRAW) ---------- */

static void add_vlan(NetState* st, uint16_t vid) {
    for(uint8_t i = 0; i < st->vlan_count; i++)
        if(st->vlans[i] == vid) return;
    if(st->vlan_count < VLAN_MAX) st->vlans[st->vlan_count++] = vid;
}

static void add_host(NetState* st, const uint8_t ip[4], const uint8_t mac[6]) {
    if(IP_ZERO(ip)) return;
    for(uint8_t i = 0; i < st->arp_count; i++) {
        if(!memcmp(st->arp[i].ip, ip, 4)) {
            memcpy(st->arp[i].mac, mac, 6);
            return;
        }
    }
    if(st->arp_count >= ARP_MAX) return;
    /* keep the list sorted by IP */
    uint8_t pos = st->arp_count;
    while(pos > 0 && memcmp(st->arp[pos - 1].ip, ip, 4) > 0) {
        st->arp[pos] = st->arp[pos - 1];
        pos--;
    }
    memcpy(st->arp[pos].ip, ip, 4);
    memcpy(st->arp[pos].mac, mac, 6);
    st->arp_count++;
}

static const char* mau_name(uint16_t mau) {
    switch(mau) {
    case 10:
        return "10 HD";
    case 11:
        return "10 FD";
    case 15:
        return "100 HD";
    case 16:
        return "100 FD";
    case 29:
        return "1G HD";
    case 30:
        return "1G FD";
    case 0:
        return "";
    default:
        return NULL;
    }
}

static void parse_lldp(App* app, const uint8_t* p, size_t len) {
    Neighbor n = {0};
    strlcpy(n.proto, "LLDP", sizeof(n.proto));
    char chassis[STR_SHORT] = {0};
    size_t i = 0;
    while(i + 2 <= len) {
        uint16_t th = rd16(p + i);
        uint8_t type = th >> 9;
        uint16_t tl = th & 0x1FF;
        const uint8_t* v = p + i + 2;
        i += 2;
        if(type == 0 || i + tl > len) break;
        switch(type) {
        case 1: /* chassis id */
            if(tl >= 7 && v[0] == 4)
                mac_str(chassis, sizeof(chassis), v + 1);
            else if(tl > 1)
                copy_str(chassis, sizeof(chassis), v + 1, tl - 1);
            break;
        case 2: /* port id */
            if(tl >= 7 && v[0] == 3)
                mac_str(n.port_id, sizeof(n.port_id), v + 1);
            else if(tl > 1)
                copy_str(n.port_id, sizeof(n.port_id), v + 1, tl - 1);
            break;
        case 3:
            if(tl >= 2) n.ttl = rd16(v);
            break;
        case 4:
            copy_str(n.port_desc, sizeof(n.port_desc), v, tl);
            break;
        case 5:
            copy_str(n.sys_name, sizeof(n.sys_name), v, tl);
            break;
        case 6:
            copy_str(n.platform, sizeof(n.platform), v, tl);
            break;
        case 8: /* management address */
            if(tl >= 6 && v[0] == 5 && v[1] == 1) {
                memcpy(n.mgmt_ip, v + 2, 4);
                n.has_mgmt = true;
            }
            break;
        case 127:
            if(tl < 4) break;
            if(v[0] == 0x00 && v[1] == 0x80 && v[2] == 0xC2 && v[3] == 1 && tl >= 6) {
                n.vlan = rd16(v + 4);
            } else if(v[0] == 0x00 && v[1] == 0x12 && v[2] == 0x0F && v[3] == 1 && tl >= 9) {
                const char* mau = mau_name(rd16(v + 7));
                if(mau)
                    snprintf(n.duplex, sizeof(n.duplex), "%s%s", (v[4] & 0x02) ? "AN " : "", mau);
                else
                    snprintf(n.duplex, sizeof(n.duplex), "MAU %u", rd16(v + 7));
            } else if(v[0] == 0x00 && v[1] == 0x12 && v[2] == 0x0F && v[3] == 2 && tl >= 7) {
                uint8_t cls = v[6] ? v[6] - 1 : 0;
                if(tl >= 12) {
                    uint16_t alloc = rd16(v + 10);
                    snprintf(n.poe, sizeof(n.poe), "class %u, %u.%uW", cls, alloc / 10, alloc % 10);
                } else {
                    snprintf(n.poe, sizeof(n.poe), "class %u", cls);
                }
            } else if(v[0] == 0x00 && v[1] == 0x12 && v[2] == 0xBB && v[3] == 2 && tl >= 8) {
                uint32_t pol = ((uint32_t)v[5] << 16) | ((uint32_t)v[6] << 8) | v[7];
                if(v[4] == 1) n.voice_vlan = (pol >> 9) & 0xFFF;
            }
            break;
        }
        i += tl;
    }
    if(!n.sys_name[0]) strlcpy(n.sys_name, chassis, sizeof(n.sys_name));
    n.valid = true;
    n.seen_tick = furi_get_tick();

    LOCK(app);
    bool fresh = !app->st.neighbor.valid || strcmp(app->st.neighbor.sys_name, n.sys_name) ||
                 strcmp(app->st.neighbor.port_id, n.port_id);
    app->st.neighbor = n;
    UNLOCK(app);
    if(fresh) app_log(app, "LLDP: %s port %s", n.sys_name, n.port_id);
}

static void parse_cdp(App* app, const uint8_t* p, size_t len) {
    if(len < 4) return;
    Neighbor n = {0};
    strlcpy(n.proto, "CDP", sizeof(n.proto));
    n.ttl = p[1];
    size_t i = 4;
    while(i + 4 <= len) {
        uint16_t type = rd16(p + i);
        uint16_t tl = rd16(p + i + 2);
        if(tl < 4 || i + tl > len) break;
        const uint8_t* v = p + i + 4;
        uint16_t vl = tl - 4;
        switch(type) {
        case 0x0001:
            copy_str(n.sys_name, sizeof(n.sys_name), v, vl);
            break;
        case 0x0002: {
            if(vl < 4) break;
            uint32_t cnt = rd32(v);
            size_t j = 4;
            for(uint32_t k = 0; k < cnt && j + 2 <= vl; k++) {
                uint8_t ptype = v[j];
                uint8_t plen = v[j + 1];
                if(j + 2 + plen + 2 > vl) break;
                uint16_t alen = rd16(v + j + 2 + plen);
                const uint8_t* a = v + j + 4 + plen;
                if(j + 4 + plen + alen > vl) break;
                if(ptype == 1 && plen == 1 && v[j + 2] == 0xCC && alen == 4 && !n.has_mgmt) {
                    memcpy(n.mgmt_ip, a, 4);
                    n.has_mgmt = true;
                }
                j += 4 + plen + alen;
            }
            break;
        }
        case 0x0003:
            copy_str(n.port_id, sizeof(n.port_id), v, vl);
            break;
        case 0x0006:
            copy_str(n.platform, sizeof(n.platform), v, vl);
            break;
        case 0x000A:
            if(vl >= 2) n.vlan = rd16(v);
            break;
        case 0x000B:
            if(vl >= 1) strlcpy(n.duplex, v[0] ? "full" : "half", sizeof(n.duplex));
            break;
        case 0x000E:
            if(vl >= 3) n.voice_vlan = rd16(v + 1);
            break;
        }
        i += tl;
    }
    n.valid = true;
    n.seen_tick = furi_get_tick();

    LOCK(app);
    bool fresh = !app->st.neighbor.valid || strcmp(app->st.neighbor.sys_name, n.sys_name) ||
                 strcmp(app->st.neighbor.port_id, n.port_id);
    app->st.neighbor = n;
    UNLOCK(app);
    if(fresh) app_log(app, "CDP: %s port %s", n.sys_name, n.port_id);
}

static void parse_stp(App* app, const uint8_t* p, size_t len) {
    if(len < 25 || p[0] || p[1]) return;
    StpInfo s = {0};
    s.valid = true;
    s.rstp = p[2] >= 2;
    s.root_prio = rd16(p + 5);
    memcpy(s.root_mac, p + 7, 6);
    s.root_cost = rd32(p + 13);
    s.bridge_prio = rd16(p + 17);
    memcpy(s.bridge_mac, p + 19, 6);
    s.seen_tick = furi_get_tick();
    LOCK(app);
    bool fresh = !app->st.stp.valid || memcmp(app->st.stp.root_mac, s.root_mac, 6);
    app->st.stp = s;
    UNLOCK(app);
    if(fresh) app_log(app, "STP root %u/" MACF, s.root_prio, MACA(s.root_mac));
}

static void handle_frame(Worker* w, const uint8_t* f, size_t n, size_t full_len) {
    App* app = w->app;
    if(n < 14) return;
    bool bcast = !memcmp(f, ip_bcast, 4) && f[4] == 0xFF && f[5] == 0xFF;
    bool mcast = !bcast && (f[0] & 1);
    uint16_t et = rd16(f + 12);
    size_t off = 14;
    bool tagged = false;
    uint16_t vid = 0;
    if(et == 0x8100 && n >= 18) {
        tagged = true;
        vid = rd16(f + 14) & 0x0FFF;
        et = rd16(f + 16);
        off = 18;
    }

    LOCK(app);
    NetState* st = &app->st;
    st->rx_frames++;
    st->rx_bytes += full_len;
    if(bcast) st->rx_bcast++;
    if(mcast) st->rx_mcast++;
    if(tagged) {
        st->rx_tagged++;
        add_vlan(st, vid);
    }
    if(et == 0x0806) {
        st->rx_arp++;
        /* passive discovery: sender of any ARP is a live host */
        if(n >= off + 28 && rd16(f + off) == 1 && rd16(f + off + 2) == 0x0800) {
            add_host(st, f + off + 14, f + off + 8);
        }
    } else if(et == 0x0800) {
        st->rx_ipv4++;
    } else if(et == 0x86DD) {
        st->rx_ipv6++;
    } else {
        st->rx_other++;
    }
    UNLOCK(app);
    w->frames_sec++;
    if(bcast) w->bcast_sec++;

    if(et == 0x88CC) {
        parse_lldp(app, f + off, n - off);
    } else if(et <= 1500 && n >= off + 3) {
        const uint8_t* llc = f + off;
        if(llc[0] == 0x42 && llc[1] == 0x42) {
            parse_stp(app, llc + 3, n - off - 3);
        } else if(
            n >= off + 8 && llc[0] == 0xAA && llc[1] == 0xAA && llc[2] == 0x03 && llc[3] == 0 &&
            llc[4] == 0 && llc[5] == 0x0C && llc[6] == 0x20 && llc[7] == 0x00) {
            parse_cdp(app, llc + 8, n - off - 8);
        }
    }
}

static void macraw_open(void) {
    /* MFEN off: multicast LLDP/CDP/STP frames must reach the socket */
    sock_open(S_RAW, Sn_MR_MACRAW, 0, 0);
}

static void macraw_process(Worker* w) {
    for(int k = 0; k < 8; k++) {
        uint16_t rsr = sock_rx_size(S_RAW);
        if(rsr < 2) return;
        uint8_t hdr[2];
        sock_rx_read(S_RAW, 0, hdr, 2);
        uint16_t len = rd16(hdr);
        if(len < 16 || len > 1600 || len > rsr) {
            /* lost sync with the buffer: start over */
            macraw_open();
            return;
        }
        uint16_t n = len - 2;
        if(n > FRAME_MAX) n = FRAME_MAX;
        sock_rx_read(S_RAW, 2, w->frame, n);
        sock_rx_consume(S_RAW, len);
        handle_frame(w, w->frame, n, len - 2);
    }
}

/* ---------- link monitor ---------- */

static void on_link_change(Worker* w, bool up, uint8_t phy) {
    App* app = w->app;
    uint32_t now = furi_get_tick();
    LOCK(app);
    NetState* st = &app->st;
    uint32_t was = now - st->link_change_tick;
    st->link = up;
    st->link_change_tick = now;
    if(up) {
        st->link_ups++;
        if(w->was_down) {
            st->last_down_ms = was;
            st->down_ms_total += was;
        }
    } else {
        st->link_downs++;
        w->was_down = true;
        st->have_ip = false;
        st->dhcp_busy = false;
    }
    UNLOCK(app);

    if(up) {
        w->was_down = false;
        app_log(
            app,
            "Link UP %s %s",
            (phy & PHY_SPD) ? "100M" : "10M",
            (phy & PHY_DPX) ? "full" : "half");
        if(app->settings.dhcp) {
            w->dhcp_pending = true;
            w->dhcp_renew = false;
        } else {
            w5500_set_net(app->settings.ip, app->settings.mask, app->settings.gw);
            LOCK(app);
            memcpy(st->ip, app->settings.ip, 4);
            memcpy(st->mask, app->settings.mask, 4);
            memcpy(st->gw, app->settings.gw, 4);
            memcpy(st->dns, app->settings.dns, 4);
            st->have_ip = true;
            UNLOCK(app);
            app_log(app, "Static IP " IPF, IPA(app->settings.ip));
        }
    } else {
        if(was >= 1000)
            app_log(app, "Link DOWN after %lu s", (unsigned long)(was / 1000));
        else
            app_log(app, "Link DOWN after %lu ms", (unsigned long)was);
        if(app->settings.dhcp) w5500_set_net(ip_zero, ip_zero, ip_zero);
        w->dhcp_pending = false;
    }
    notify_link(app, up);
}

static void chip_lost(Worker* w) {
    App* app = w->app;
    LOCK(app);
    bool had_link = app->st.link;
    app->st.chip_ok = false;
    app->st.link = false;
    app->st.have_ip = false;
    app->st.ping_running = false;
    UNLOCK(app);
    app_log(app, "W5500 lost (check wiring)");
    if(had_link) notify_link(app, false);
    w->chip_tick = furi_get_tick();
}

static void worker_poll(Worker* w) {
    App* app = w->app;
    if(!app->st.chip_ok) return;
    uint32_t now = furi_get_tick();

    if(now - w->ver_tick >= 1000) {
        w->ver_tick = now;
        if(w5500_version() != 0x04) {
            chip_lost(w);
            return;
        }
        if(sock_status(S_RAW) != SOCK_MACRAW) macraw_open();
    }

    if(now - w->phy_tick >= 20) {
        w->phy_tick = now;
        uint8_t phy = w5500_phy();
        bool up = phy & PHY_LNK;
        bool changed_mode = up && app->st.link && ((phy ^ app->st.phy) & (PHY_SPD | PHY_DPX));
        LOCK(app);
        app->st.phy = phy;
        UNLOCK(app);
        if(up != app->st.link) on_link_change(w, up, phy);
        if(changed_mode)
            app_log(
                app,
                "Link now %s %s",
                (phy & PHY_SPD) ? "100M" : "10M",
                (phy & PHY_DPX) ? "full" : "half");

        uint8_t ir = w5500_read8(W5500_IR);
        if(ir & IR_CONFLICT) {
            w5500_write8(W5500_IR, IR_CONFLICT);
            LOCK(app);
            app->st.conflicts++;
            UNLOCK(app);
            app_log(app, "IP CONFLICT on " IPF, IPA(app->st.ip));
            notification_message(app->notifications, &sequence_error);
        }
        if(ir & IR_UNREACH) w5500_write8(W5500_IR, IR_UNREACH);
    }

    macraw_process(w);

    if(now - w->sec_tick >= 1000) {
        LOCK(app);
        app->st.pps = w->frames_sec;
        app->st.bcast_pps = w->bcast_sec;
        if(w->frames_sec > app->st.pps_peak) app->st.pps_peak = w->frames_sec;
        UNLOCK(app);
        if(w->bcast_sec >= 300 && !w->storm)
            app_log(app, "Broadcast storm? %lu/s", (unsigned long)w->bcast_sec);
        if(w->bcast_sec < 100 && w->storm) app_log(app, "Broadcast rate normal");
        if(w->bcast_sec >= 300) w->storm = true;
        if(w->bcast_sec < 100) w->storm = false;
        w->frames_sec = 0;
        w->bcast_sec = 0;
        w->sec_tick = now;
    }
}

/* ---------- UDP / IPRAW receive ---------- */

static int udp_recv(uint8_t s, uint8_t* buf, uint16_t max, uint8_t from[4]) {
    uint16_t rsr = sock_rx_size(s);
    if(rsr < 8) return -1;
    uint8_t hdr[8];
    sock_rx_read(s, 0, hdr, 8);
    uint16_t len = rd16(hdr + 6);
    uint16_t n = len < max ? len : max;
    sock_rx_read(s, 8, buf, n);
    sock_rx_consume(s, 8 + len);
    if(from) memcpy(from, hdr, 4);
    return n;
}

static int ipraw_recv(uint8_t s, uint8_t* buf, uint16_t max, uint8_t from[4]) {
    uint16_t rsr = sock_rx_size(s);
    if(rsr < 6) return -1;
    uint8_t hdr[6];
    sock_rx_read(s, 0, hdr, 6);
    uint16_t len = rd16(hdr + 4);
    uint16_t n = len < max ? len : max;
    sock_rx_read(s, 6, buf, n);
    sock_rx_consume(s, 6 + len);
    if(from) memcpy(from, hdr, 4);
    return n;
}

/* ---------- DHCP ---------- */

typedef struct {
    uint8_t type;
    uint8_t yiaddr[4];
    uint8_t server[4];
    uint8_t mask[4];
    uint8_t router[4];
    uint8_t dns[4];
    uint32_t lease;
} DhcpReply;

static uint16_t dhcp_build(
    uint8_t* b,
    uint8_t type,
    uint32_t xid,
    const uint8_t mac[6],
    const uint8_t* req_ip,
    const uint8_t* server) {
    memset(b, 0, 300);
    b[0] = 1;
    b[1] = 1;
    b[2] = 6;
    b[4] = xid >> 24;
    b[5] = xid >> 16;
    b[6] = xid >> 8;
    b[7] = xid;
    b[10] = 0x80; /* broadcast flag: the W5500 has no IP yet */
    memcpy(b + 28, mac, 6);
    uint16_t i = 236;
    b[i++] = 99;
    b[i++] = 130;
    b[i++] = 83;
    b[i++] = 99;
    b[i++] = 53;
    b[i++] = 1;
    b[i++] = type;
    b[i++] = 61;
    b[i++] = 7;
    b[i++] = 1;
    memcpy(b + i, mac, 6);
    i += 6;
    b[i++] = 12;
    b[i++] = 7;
    memcpy(b + i, "flipper", 7);
    i += 7;
    if(req_ip) {
        b[i++] = 50;
        b[i++] = 4;
        memcpy(b + i, req_ip, 4);
        i += 4;
    }
    if(server) {
        b[i++] = 54;
        b[i++] = 4;
        memcpy(b + i, server, 4);
        i += 4;
    }
    b[i++] = 55;
    b[i++] = 5;
    b[i++] = 1;
    b[i++] = 3;
    b[i++] = 6;
    b[i++] = 51;
    b[i++] = 54;
    b[i++] = 255;
    return i < 300 ? 300 : i;
}

static bool dhcp_parse(const uint8_t* b, int len, uint32_t xid, DhcpReply* r) {
    if(len < 240 || b[0] != 2 || rd32(b + 4) != xid) return false;
    if(b[236] != 99 || b[237] != 130 || b[238] != 83 || b[239] != 99) return false;
    memset(r, 0, sizeof(*r));
    memcpy(r->yiaddr, b + 16, 4);
    int i = 240;
    while(i < len) {
        uint8_t opt = b[i++];
        if(opt == 0) continue;
        if(opt == 255 || i >= len) break;
        uint8_t ol = b[i++];
        if(i + ol > len) break;
        const uint8_t* v = b + i;
        switch(opt) {
        case 53:
            r->type = v[0];
            break;
        case 1:
            if(ol >= 4) memcpy(r->mask, v, 4);
            break;
        case 3:
            if(ol >= 4) memcpy(r->router, v, 4);
            break;
        case 6:
            if(ol >= 4) memcpy(r->dns, v, 4);
            break;
        case 51:
            if(ol >= 4) r->lease = rd32(v);
            break;
        case 54:
            if(ol >= 4) memcpy(r->server, v, 4);
            break;
        }
        i += ol;
    }
    return r->type != 0;
}

/* Wait for a DHCP reply of the wanted type. */
static bool dhcp_wait(Worker* w, uint32_t xid, uint8_t want, DhcpReply* r, uint32_t ms) {
    uint32_t start = furi_get_tick();
    while(furi_get_tick() - start < ms) {
        int n = udp_recv(S_DHCP, w->pkt, sizeof(w->pkt), NULL);
        if(n > 0 && dhcp_parse(w->pkt, n, xid, r)) {
            if(r->type == want || r->type == DHCP_NAK) return true;
        }
        if(!wait_ms(w, 5)) return false;
    }
    return false;
}

static void run_dhcp(Worker* w, bool renew) {
    App* app = w->app;
    NetState* st = &app->st;
    uint8_t cur_ip[4];
    memcpy(cur_ip, st->ip, 4);
    LOCK(app);
    st->dhcp_busy = true;
    if(!renew) st->have_ip = false;
    UNLOCK(app);
    if(!renew) w5500_set_net(ip_zero, ip_zero, ip_zero);
    if(!sock_open(S_DHCP, Sn_MR_UDP, 68, 0)) {
        app_log(app, "DHCP: socket error");
        goto done;
    }

    uint32_t t0 = furi_get_tick();
    uint32_t xid = furi_hal_random_get();
    bool ok = false;
    if(!renew) app_log(app, "DHCP: discover");
    for(int attempt = 0; attempt < 4 && !ok; attempt++) {
        DhcpReply offer, ack;
        uint16_t len = dhcp_build(
            w->pkt, DHCP_DISCOVER, xid, st->mac, renew ? cur_ip : NULL, NULL);
        sock_sendto(S_DHCP, w->pkt, len, ip_bcast, 67);
        if(!dhcp_wait(w, xid, DHCP_OFFER, &offer, 3000)) {
            if(abort_requested(w)) break;
            continue;
        }
        if(offer.type == DHCP_NAK) continue;
        len = dhcp_build(w->pkt, DHCP_REQUEST, xid, st->mac, offer.yiaddr, offer.server);
        sock_sendto(S_DHCP, w->pkt, len, ip_bcast, 67);
        if(!dhcp_wait(w, xid, DHCP_ACK, &ack, 3000)) {
            if(abort_requested(w)) break;
            continue;
        }
        if(ack.type == DHCP_NAK) {
            app_log(app, "DHCP: NAK from " IPF, IPA(offer.server));
            renew = false;
            continue;
        }
        if(IP_ZERO(ack.mask)) memcpy(ack.mask, offer.mask, 4);
        if(IP_ZERO(ack.router)) memcpy(ack.router, offer.router, 4);
        if(IP_ZERO(ack.dns)) memcpy(ack.dns, offer.dns, 4);
        if(IP_ZERO(ack.server)) memcpy(ack.server, offer.server, 4);
        w5500_set_net(ack.yiaddr, ack.mask, ack.router);
        LOCK(app);
        memcpy(st->ip, ack.yiaddr, 4);
        memcpy(st->mask, ack.mask, 4);
        memcpy(st->gw, ack.router, 4);
        memcpy(st->dns, ack.dns, 4);
        memcpy(st->dhcp_server, ack.server, 4);
        st->lease = ack.lease;
        st->lease_tick = furi_get_tick();
        st->dhcp_ms = furi_get_tick() - t0;
        st->have_ip = true;
        UNLOCK(app);
        ok = true;
        if(renew && !memcmp(cur_ip, ack.yiaddr, 4)) {
            app_log(app, "DHCP: renewed " IPF, IPA(ack.yiaddr));
        } else {
            app_log(
                app, "DHCP: " IPF " in %lu ms", IPA(ack.yiaddr), (unsigned long)st->dhcp_ms);
            app_log(app, "GW " IPF " DNS " IPF, IPA(ack.router), IPA(ack.dns));
        }
    }
    sock_close(S_DHCP);
    if(!ok && st->link && st->chip_ok && !(furi_thread_flags_get() & (WF_EXIT | WF_APPLY))) {
        app_log(app, "DHCP: no answer, retry in 30s");
    }
    w->dhcp_retry_tick = ok ? 0 : furi_get_tick();
done:
    LOCK(app);
    st->dhcp_busy = false;
    UNLOCK(app);
}

static void run_dhcp_scan(Worker* w) {
    App* app = w->app;
    NetState* st = &app->st;
    LOCK(app);
    st->dhcps_busy = true;
    st->dhcps_done = false;
    st->dhcps_count = 0;
    UNLOCK(app);
    app_log(app, "DHCP server scan");
    if(sock_open(S_DHCP, Sn_MR_UDP, 68, 0)) {
        uint32_t xid = furi_hal_random_get();
        uint16_t len = dhcp_build(w->pkt, DHCP_DISCOVER, xid, st->mac, NULL, NULL);
        for(int round = 0; round < 2; round++) {
            sock_sendto(S_DHCP, w->pkt, len, ip_bcast, 67);
            uint32_t start = furi_get_tick();
            while(furi_get_tick() - start < 2500) {
                uint8_t from[4];
                int n = udp_recv(S_DHCP, w->frame, sizeof(w->frame), from);
                DhcpReply r;
                if(n > 0 && dhcp_parse(w->frame, n, xid, &r) && r.type == DHCP_OFFER) {
                    if(IP_ZERO(r.server)) memcpy(r.server, from, 4);
                    LOCK(app);
                    bool known = false;
                    for(uint8_t i = 0; i < st->dhcps_count; i++)
                        if(!memcmp(st->dhcps[i].server, r.server, 4)) known = true;
                    if(!known && st->dhcps_count < DHCPSRV_MAX) {
                        DhcpServer* d = &st->dhcps[st->dhcps_count++];
                        memcpy(d->server, r.server, 4);
                        memcpy(d->offered, r.yiaddr, 4);
                        memcpy(d->router, r.router, 4);
                        d->lease = r.lease;
                    }
                    UNLOCK(app);
                    if(!known) app_log(app, "Offer from " IPF, IPA(r.server));
                }
                if(!wait_ms(w, 5)) break;
            }
            if(abort_requested(w)) break;
            /* new transaction id: some servers ignore a repeated discover */
            xid = furi_hal_random_get();
            len = dhcp_build(w->pkt, DHCP_DISCOVER, xid, st->mac, NULL, NULL);
        }
        sock_close(S_DHCP);
    }
    LOCK(app);
    st->dhcps_busy = false;
    st->dhcps_done = true;
    uint8_t cnt = st->dhcps_count;
    UNLOCK(app);
    if(cnt > 1)
        app_log(app, "WARNING: %u DHCP servers!", cnt);
    else
        app_log(app, "DHCP servers found: %u", cnt);
}

/* ---------- ping ---------- */

static uint16_t inet_cksum(const uint8_t* p, size_t len) {
    uint32_t sum = 0;
    for(size_t i = 0; i + 1 < len; i += 2) sum += rd16(p + i);
    if(len & 1) sum += (uint32_t)p[len - 1] << 8;
    while(sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

void ping_target_resolve(App* app, uint8_t out[4]) {
    static const uint8_t google[4] = {8, 8, 8, 8};
    static const uint8_t cf[4] = {1, 1, 1, 1};
    switch(app->settings.ping_preset) {
    case 0:
        memcpy(out, app->st.gw, 4);
        break;
    case 1:
        memcpy(out, app->st.dns, 4);
        break;
    case 2:
        memcpy(out, google, 4);
        break;
    case 3:
        memcpy(out, cf, 4);
        break;
    default:
        memcpy(out, app->settings.ping_custom, 4);
        break;
    }
}

static void ping_once(Worker* w) {
    App* app = w->app;
    NetState* st = &app->st;
    uint8_t* b = w->pkt;
    uint16_t seq = ++w->ping_seq;
    memset(b, 0, 40);
    b[0] = 8;
    b[4] = w->ping_id >> 8;
    b[5] = w->ping_id;
    b[6] = seq >> 8;
    b[7] = seq;
    for(int i = 8; i < 40; i++) b[i] = (uint8_t)('a' + (i - 8) % 23);
    uint16_t ck = inet_cksum(b, 40);
    b[2] = ck >> 8;
    b[3] = ck;

    LOCK(app);
    st->ping_sent++;
    UNLOCK(app);

    uint32_t t0 = furi_get_tick();
    W5500SendResult r = sock_sendto(S_ICMP, b, 40, st->ping_ip, 0);
    if(r != W5500SendOk) {
        LOCK(app);
        strlcpy(
            st->ping_status,
            r == W5500SendTimeout ? "no ARP reply" : "send error",
            sizeof(st->ping_status));
        ping_hist_push(st, 255);
        UNLOCK(app);
        return;
    }
    while(furi_get_tick() - t0 < 1000) {
        uint8_t from[4];
        int n = ipraw_recv(S_ICMP, w->frame, sizeof(w->frame), from);
        if(n >= 8) {
            const uint8_t* ic = w->frame;
            if(ic[0] == 0 && rd16(ic + 4) == w->ping_id && rd16(ic + 6) == seq) {
                uint32_t rtt = furi_get_tick() - t0;
                LOCK(app);
                st->ping_recv++;
                st->ping_last = rtt;
                st->ping_sum += rtt;
                if(st->ping_recv == 1 || rtt < st->ping_min) st->ping_min = rtt;
                if(rtt > st->ping_max) st->ping_max = rtt;
                snprintf(st->ping_status, sizeof(st->ping_status), "reply %lu ms", (unsigned long)rtt);
                ping_hist_push(st, rtt > 254 ? 254 : (uint8_t)rtt);
                UNLOCK(app);
                return;
            }
            /* error carries the original IP header + 8 bytes of our echo */
            if((ic[0] == 3 || ic[0] == 11) && n >= 36 && rd16(ic + 32) == w->ping_id &&
               rd16(ic + 34) == seq) {
                LOCK(app);
                snprintf(
                    st->ping_status,
                    sizeof(st->ping_status),
                    "%s from %u.%u.%u.%u",
                    ic[0] == 3 ? "unreach" : "TTL exc",
                    IPA(from));
                ping_hist_push(st, 255);
                UNLOCK(app);
                return;
            }
        }
        if(!wait_ms(w, 2)) return;
    }
    LOCK(app);
    strlcpy(st->ping_status, "timeout", sizeof(st->ping_status));
    ping_hist_push(st, 255);
    UNLOCK(app);
}

static void ping_start(Worker* w) {
    App* app = w->app;
    NetState* st = &app->st;
    uint8_t target[4];
    LOCK(app);
    ping_target_resolve(app, target);
    UNLOCK(app);
    if(!st->have_ip) {
        app_log(app, "Ping: no IP yet");
        return;
    }
    if(IP_ZERO(target)) {
        app_log(app, "Ping: no target address");
        return;
    }
    if(!sock_open(S_ICMP, Sn_MR_IPRAW, 0, 1)) {
        app_log(app, "Ping: socket error");
        return;
    }
    LOCK(app);
    memcpy(st->ping_ip, target, 4);
    st->ping_running = true;
    st->ping_sent = st->ping_recv = 0;
    st->ping_min = st->ping_max = st->ping_sum = st->ping_last = 0;
    st->ping_hist_len = 0;
    strlcpy(st->ping_status, "started", sizeof(st->ping_status));
    UNLOCK(app);
    w->ping_id = (uint16_t)furi_hal_random_get();
    w->ping_seq = 0;
    w->ping_tick = 0;
    app_log(app, "Ping " IPF, IPA(target));
}

static void ping_stop(Worker* w) {
    App* app = w->app;
    NetState* st = &app->st;
    if(!st->ping_running) return;
    sock_close(S_ICMP);
    LOCK(app);
    st->ping_running = false;
    uint32_t sent = st->ping_sent, recv = st->ping_recv;
    uint32_t avg = recv ? st->ping_sum / recv : 0;
    UNLOCK(app);
    app_log(
        app,
        "Ping %lu/%lu, avg %lu ms",
        (unsigned long)recv,
        (unsigned long)sent,
        (unsigned long)avg);
}

/* ---------- DNS ---------- */

static void run_dns(Worker* w) {
    App* app = w->app;
    NetState* st = &app->st;
    const char* name = app->settings.dns_name;
    LOCK(app);
    st->dns_busy = true;
    st->dns_ok = false;
    strlcpy(st->dns_status, "resolving...", sizeof(st->dns_status));
    UNLOCK(app);

    uint8_t server[4];
    memcpy(server, st->dns, 4);
    if(IP_ZERO(server)) memcpy(server, (const uint8_t[]){8, 8, 8, 8}, 4);

    const char* status = "no answer";
    uint8_t* b = w->pkt;
    uint16_t id = (uint16_t)furi_hal_random_get();
    memset(b, 0, 12);
    b[0] = id >> 8;
    b[1] = id;
    b[2] = 0x01; /* recursion desired */
    b[5] = 1;
    uint16_t i = 12;
    const char* p = name;
    while(*p && i < 280) {
        const char* dot = strchr(p, '.');
        size_t l = dot ? (size_t)(dot - p) : strlen(p);
        if(l == 0 || l > 63) break;
        b[i++] = (uint8_t)l;
        memcpy(b + i, p, l);
        i += l;
        p += l;
        if(*p == '.') p++;
    }
    b[i++] = 0;
    b[i++] = 0;
    b[i++] = 1;
    b[i++] = 0;
    b[i++] = 1;

    uint16_t port = 49152 + (furi_hal_random_get() % 16000);
    uint32_t t0 = furi_get_tick();
    if(!sock_open(S_DNS, Sn_MR_UDP, port, 0)) {
        status = "socket error";
    } else {
        for(int attempt = 0; attempt < 3; attempt++) {
            W5500SendResult r = sock_sendto(S_DNS, b, i, server, 53);
            if(r == W5500SendTimeout) {
                status = "no ARP reply";
                break;
            }
            uint32_t start = furi_get_tick();
            bool got = false;
            while(furi_get_tick() - start < 2000) {
                int n = udp_recv(S_DNS, w->frame, sizeof(w->frame), NULL);
                const uint8_t* a = w->frame;
                if(n >= 12 && rd16(a) == id) {
                    got = true;
                    uint8_t rcode = a[3] & 0x0F;
                    if(rcode == 3) {
                        status = "NXDOMAIN";
                        break;
                    }
                    if(rcode) {
                        status = "server error";
                        break;
                    }
                    uint16_t qd = rd16(a + 4), an = rd16(a + 6);
                    int k = 12;
                    for(uint16_t q = 0; q < qd && k < n; q++) {
                        while(k < n && a[k] && (a[k] & 0xC0) != 0xC0) k += a[k] + 1;
                        k += (k < n && (a[k] & 0xC0) == 0xC0) ? 2 : 1;
                        k += 4;
                    }
                    status = "no A record";
                    for(uint16_t q = 0; q < an && k + 10 <= n; q++) {
                        while(k < n && a[k] && (a[k] & 0xC0) != 0xC0) k += a[k] + 1;
                        k += (k < n && (a[k] & 0xC0) == 0xC0) ? 2 : 1;
                        if(k + 10 > n) break;
                        uint16_t type = rd16(a + k), rdlen = rd16(a + k + 8);
                        k += 10;
                        if(type == 1 && rdlen == 4 && k + 4 <= n) {
                            LOCK(app);
                            memcpy(st->dns_result, a + k, 4);
                            st->dns_ok = true;
                            UNLOCK(app);
                            status = NULL;
                            break;
                        }
                        k += rdlen;
                    }
                    break;
                }
                if(!wait_ms(w, 5)) break;
            }
            if(got || abort_requested(w)) break;
        }
        sock_close(S_DNS);
    }
    uint32_t ms = furi_get_tick() - t0;
    LOCK(app);
    st->dns_ms = ms;
    st->dns_busy = false;
    if(status)
        strlcpy(st->dns_status, status, sizeof(st->dns_status));
    else
        snprintf(st->dns_status, sizeof(st->dns_status), "%lu ms", (unsigned long)ms);
    UNLOCK(app);
    if(status)
        app_log(app, "DNS %s: %s", name, status);
    else
        app_log(app, "DNS %s=" IPF, name, IPA(st->dns_result));
}

/* ---------- ARP scan ---------- */

static void run_arp_scan(Worker* w) {
    App* app = w->app;
    NetState* st = &app->st;
    if(!st->have_ip) {
        app_log(app, "Scan: no IP yet");
        return;
    }
    uint32_t ip = rd32(st->ip), mask = rd32(st->mask);
    if(mask < 0xFFFFFC00) mask = 0xFFFFFF00; /* bigger than /22: scan our /24 */
    uint32_t net = ip & mask;
    uint32_t total = (~mask) - 1;
    if(mask >= 0xFFFFFFFE) total = 0;

    LOCK(app);
    st->arp_busy = true;
    st->arp_count = 0;
    st->arp_done = 0;
    st->arp_total = (uint16_t)total;
    UNLOCK(app);
    app_log(app, "Scan %lu hosts", (unsigned long)total);

    /* one ARP request, 150 ms wait, one retry */
    w5500_set_retry(1500, 1);
    uint32_t inflight[S_ARPN] = {0};
    bool busy[S_ARPN] = {0};
    for(uint8_t k = 0; k < S_ARPN; k++) sock_open(S_ARP0 + k, Sn_MR_UDP, 40000 + k, 0);

    uint32_t next = 1, done = 0;
    uint8_t probe = 0;
    while(done < total) {
        for(uint8_t k = 0; k < S_ARPN; k++) {
            uint8_t s = S_ARP0 + k;
            if(busy[k]) {
                bool fin;
                W5500SendResult r = sock_send_poll(s, &fin);
                if(!fin) continue;
                busy[k] = false;
                done++;
                if(r == W5500SendOk) {
                    uint8_t mac[6], hip[4] = {
                                        inflight[k] >> 24,
                                        inflight[k] >> 16,
                                        inflight[k] >> 8,
                                        inflight[k]};
                    sock_get_dhar(s, mac);
                    LOCK(app);
                    add_host(st, hip, mac);
                    UNLOCK(app);
                }
            }
            if(!busy[k] && next <= total) {
                uint32_t h = net + next++;
                if(h == ip) {
                    done++;
                    continue;
                }
                uint8_t hip[4] = {h >> 24, h >> 16, h >> 8, h};
                inflight[k] = h;
                busy[k] = sock_sendto_begin(s, &probe, 1, hip, 9);
                if(!busy[k]) done++;
            }
        }
        LOCK(app);
        st->arp_done = (uint16_t)done;
        UNLOCK(app);
        if(!wait_ms(w, 3)) break;
    }
    for(uint8_t k = 0; k < S_ARPN; k++) sock_close(S_ARP0 + k);
    w5500_set_retry(2000, 3);
    /* our own address is not probed: add it so the list is complete */
    LOCK(app);
    add_host(st, st->ip, st->mac);
    st->arp_busy = false;
    uint8_t cnt = st->arp_count;
    UNLOCK(app);
    app_log(app, "Scan done: %u hosts", cnt);
}

/* ---------- Wake-on-LAN ---------- */

static void run_wol(Worker* w) {
    App* app = w->app;
    uint8_t* b = w->pkt;
    memset(b, 0xFF, 6);
    memcpy(b + 6, app->st.mac, 6);
    b[12] = 0x08;
    b[13] = 0x42;
    memset(b + 14, 0xFF, 6);
    for(int i = 0; i < 16; i++) memcpy(b + 20 + i * 6, app->settings.wol_mac, 6);
    W5500SendResult r = sock_send_raw(S_RAW, b, 116);
    LOCK(app);
    snprintf(
        app->st.wol_status,
        sizeof(app->st.wol_status),
        r == W5500SendOk ? "sent" : "send failed");
    UNLOCK(app);
    app_log(app, "WoL " MACF " %s", MACA(app->settings.wol_mac), r == W5500SendOk ? "sent" : "failed");
}

/* ---------- setup ---------- */

static void make_mac(App* app, uint8_t mac[6]) {
    switch(app->settings.mac_mode) {
    case MacRandom:
        furi_hal_random_fill_buf(mac, 6);
        mac[0] = (mac[0] & 0xFE) | 0x02;
        break;
    case MacCustom:
        memcpy(mac, app->settings.custom_mac, 6);
        break;
    default:
        settings_device_mac(mac);
        break;
    }
}

static bool chip_setup(Worker* w) {
    App* app = w->app;
    uint8_t mac[6];
    make_mac(app, mac);
    if(!w5500_init(mac)) return false;
    static const uint8_t opmdc[PhyModeCount] = {7, 3, 2, 1, 0};
    w5500_phy_set_mode(opmdc[app->settings.phy_mode % PhyModeCount]);
    w5500_set_net(ip_zero, ip_zero, ip_zero);
    w5500_write8(W5500_IR, 0xFF);
    macraw_open();

    LOCK(app);
    NetState* st = &app->st;
    memcpy(st->mac, mac, 6);
    st->chip_ok = true;
    st->link = false;
    st->have_ip = false;
    st->link_change_tick = furi_get_tick();
    st->ping_running = false;
    UNLOCK(app);
    w->dhcp_pending = false;
    w->was_down = false;
    w->chip_missing_logged = false;
    app_log(app, "W5500 ok, PHY %s", phy_mode_name(app->settings.phy_mode));
    app_log(app, "MAC " MACF, MACA(mac));
    return true;
}

static void clear_stats(App* app) {
    LOCK(app);
    NetState* st = &app->st;
    st->link_ups = st->link ? 1 : 0;
    st->link_downs = 0;
    st->down_ms_total = 0;
    st->last_down_ms = 0;
    st->conflicts = 0;
    st->rx_frames = st->rx_bytes = st->rx_bcast = st->rx_mcast = 0;
    st->rx_arp = st->rx_ipv4 = st->rx_ipv6 = st->rx_other = st->rx_tagged = 0;
    st->pps_peak = 0;
    st->vlan_count = 0;
    memset(&st->neighbor, 0, sizeof(st->neighbor));
    memset(&st->stp, 0, sizeof(st->stp));
    st->session_tick = furi_get_tick();
    UNLOCK(app);
    app_log(app, "Counters cleared");
}

int32_t worker_thread(void* ctx) {
    App* app = ctx;
    Worker* w = malloc(sizeof(Worker));
    memset(w, 0, sizeof(Worker));
    w->app = app;
    w5500_bus_init();
    app_log(app, "Start");

    while(true) {
        uint32_t flags = furi_thread_flags_wait(WF_ALL, FuriFlagWaitAny, 5);
        if(flags & FuriFlagError) flags = 0;
        if(flags & WF_EXIT) break;
        NetState* st = &app->st;

        if(flags & WF_APPLY) {
            if(st->chip_ok) {
                ping_stop(w);
                app_log(app, "Applying settings");
            }
            LOCK(app);
            st->chip_ok = false;
            st->link = false;
            st->have_ip = false;
            UNLOCK(app);
            w->chip_tick = 0;
        }

        if(!st->chip_ok) {
            if(!w->chip_tick || furi_get_tick() - w->chip_tick >= 1000) {
                w->chip_tick = furi_get_tick();
                if(!chip_setup(w) && !w->chip_missing_logged) {
                    app_log(app, "W5500 not found");
                    w->chip_missing_logged = true;
                }
            }
            continue;
        }

        worker_poll(w);
        if(!st->chip_ok) continue;

        if(flags & WF_CLEAR) clear_stats(app);
        if(flags & WF_PING_STOP) ping_stop(w);
        if(flags & WF_WOL) run_wol(w);

        bool need_link = flags & (WF_PING | WF_DNS | WF_ARP | WF_DHCPSCAN | WF_DHCP);
        if(need_link && !st->link) {
            app_log(app, "No link");
            continue;
        }

        if(flags & WF_DHCP) {
            if(app->settings.dhcp) {
                w->dhcp_pending = true;
                w->dhcp_renew = false;
            } else {
                app_log(app, "Static IP mode");
            }
        }
        if(st->link && app->settings.dhcp) {
            if(!w->dhcp_pending && !st->have_ip && w->dhcp_retry_tick &&
               furi_get_tick() - w->dhcp_retry_tick > 30000) {
                w->dhcp_pending = true;
            }
            if(!w->dhcp_pending && st->have_ip && st->lease &&
               furi_get_tick() - st->lease_tick > (uint64_t)st->lease * 500) {
                w->dhcp_pending = true;
                w->dhcp_renew = true;
            }
        }
        if(w->dhcp_pending && st->link) {
            w->dhcp_pending = false;
            run_dhcp(w, w->dhcp_renew && st->have_ip);
            w->dhcp_renew = false;
        }

        if(flags & WF_DHCPSCAN) run_dhcp_scan(w);
        if(flags & WF_PING) ping_start(w);
        if(flags & WF_DNS) {
            if(st->have_ip)
                run_dns(w);
            else
                app_log(app, "DNS: no IP yet");
        }
        if(flags & WF_ARP) run_arp_scan(w);

        if(st->ping_running) {
            if(!st->link || !st->have_ip) {
                ping_stop(w);
            } else if(!w->ping_tick || furi_get_tick() - w->ping_tick >= 1000) {
                w->ping_tick = furi_get_tick();
                ping_once(w);
            }
        }
    }

    ping_stop(w);
    for(uint8_t s = 0; s < 8; s++) sock_close(s);
    w5500_bus_deinit();
    free(w);
    return 0;
}
