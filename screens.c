#include "rj45_tester.h"
#include "w5500.h"

#include <gui/elements.h>

const char* const ping_preset_names[] = {"Gateway", "DNS", "8.8.8.8", "1.1.1.1", "Custom"};

#define LINE_H 9
#define TOP    10

static const char* screen_title(Screen s) {
    switch(s) {
    case ScreenStatus:
        return "Link status";
    case ScreenNeighbors:
        return "Switch / neighbors";
    case ScreenPing:
        return "Ping";
    case ScreenDns:
        return "DNS lookup";
    case ScreenArp:
        return "Hosts (ARP)";
    case ScreenDhcp:
        return "DHCP servers";
    case ScreenTraffic:
        return "Traffic";
    case ScreenLog:
        return "Event log";
    case ScreenWol:
        return "Wake-on-LAN";
    case ScreenAbout:
        return "Wiring";
    }
    return "";
}

static void fmt_dur(char* buf, size_t size, uint32_t ms) {
    uint32_t s = ms / 1000;
    if(s < 60)
        snprintf(buf, size, "%lus", (unsigned long)s);
    else if(s < 3600)
        snprintf(buf, size, "%lum%02lus", (unsigned long)(s / 60), (unsigned long)(s % 60));
    else
        snprintf(
            buf,
            size,
            "%luh%02lum",
            (unsigned long)(s / 3600),
            (unsigned long)((s / 60) % 60));
}

static void fmt_count(char* buf, size_t size, uint32_t v) {
    if(v < 10000)
        snprintf(buf, size, "%lu", (unsigned long)v);
    else if(v < 10000000)
        snprintf(buf, size, "%luk", (unsigned long)(v / 1000));
    else
        snprintf(buf, size, "%luM", (unsigned long)(v / 1000000));
}

/* Lines are drawn into a virtual list; scroll moves through it. */
typedef struct {
    Canvas* canvas;
    int16_t scroll;
    int16_t line;
    int16_t visible;
    int16_t y0;
} Lines;

static void line(Lines* l, const char* fmt, ...) _ATTRIBUTE((__format__(__printf__, 2, 3)));
static void line(Lines* l, const char* fmt, ...) {
    int16_t row = l->line - l->scroll;
    l->line++;
    if(row < 0 || row >= l->visible) return;
    char buf[48];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    canvas_draw_str(l->canvas, 0, l->y0 + LINE_H * (row + 1) - 1, buf);
}

static void draw_header(Canvas* canvas, App* app, const char* right) {
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 0, 9, screen_title(app->screen));
    if(right) {
        canvas_set_font(canvas, FontSecondary);
        canvas_draw_str_aligned(canvas, 127, 1, AlignRight, AlignTop, right);
    }
    canvas_draw_line(canvas, 0, TOP, 127, TOP);
    canvas_set_font(canvas, FontSecondary);
}

static void draw_status(Canvas* canvas, App* app) {
    NetState* st = &app->st;
    char a[16], b[16];
    uint32_t now = furi_get_tick();

    canvas_set_font(canvas, FontPrimary);
    if(!st->chip_ok) {
        canvas_draw_str(canvas, 0, 9, "W5500 not found");
        canvas_set_font(canvas, FontSecondary);
        canvas_draw_str(canvas, 0, 22, "Check wiring: Menu > Wiring");
        canvas_draw_str(canvas, 0, 31, "Retrying every second...");
        return;
    }
    /* big link badge */
    if(st->link) {
        canvas_draw_rbox(canvas, 0, 0, 40, 14, 2);
        canvas_set_color(canvas, ColorWhite);
        canvas_draw_str(canvas, 4, 11, "LINK");
        canvas_set_color(canvas, ColorBlack);
        snprintf(
            a,
            sizeof(a),
            "%s %s",
            (st->phy & PHY_SPD) ? "100M" : "10M",
            (st->phy & PHY_DPX) ? "Full" : "Half");
        canvas_draw_str(canvas, 44, 11, a);
    } else {
        canvas_draw_rframe(canvas, 0, 0, 40, 14, 2);
        canvas_draw_str(canvas, 4, 11, "DOWN");
        canvas_set_font(canvas, FontSecondary);
        canvas_draw_str(canvas, 44, 10, "no cable / no peer");
    }
    canvas_set_font(canvas, FontSecondary);
    fmt_dur(b, sizeof(b), now - st->link_change_tick);
    canvas_draw_str_aligned(canvas, 127, 2, AlignRight, AlignTop, b);

    /* four lines between the badge and the footer */
    Lines l = {canvas, app->scroll, 0, 4, 15};
    canvas_draw_line(canvas, 0, 15, 127, 15);

    if(st->have_ip) {
        line(&l, "IP  " IPF, IPA(st->ip));
        uint32_t m = (st->mask[0] << 24) | (st->mask[1] << 16) | (st->mask[2] << 8) | st->mask[3];
        int prefix = 0;
        while(m & 0x80000000) {
            prefix++;
            m <<= 1;
        }
        line(&l, "Mask /%d  GW " IPF, prefix, IPA(st->gw));
        line(&l, "DNS " IPF, IPA(st->dns));
        if(app->settings.dhcp) {
            line(&l, "DHCP " IPF " %lums", IPA(st->dhcp_server), (unsigned long)st->dhcp_ms);
            if(st->lease) {
                uint64_t total = (uint64_t)st->lease * 1000, used = now - st->lease_tick;
                if(st->lease == 0xFFFFFFFF) {
                    line(&l, "Lease: infinite");
                } else {
                    fmt_dur(a, sizeof(a), used < total ? (uint32_t)MIN(total - used, 0xFFFFFFFFULL) : 0);
                    line(&l, "Lease left %s", a);
                }
            }
        } else {
            line(&l, "Static address");
        }
    } else if(st->dhcp_busy) {
        line(&l, "DHCP: waiting for server...");
    } else if(st->link) {
        line(&l, "No IP address");
    } else {
        line(&l, "Plug the cable in");
    }
    line(&l, "Flaps: %lu down, last %lus", (unsigned long)st->link_downs, (unsigned long)(st->last_down_ms / 1000));
    fmt_dur(a, sizeof(a), st->down_ms_total);
    line(&l, "Total down %s", a);
    if(st->conflicts) line(&l, "IP CONFLICTS: %lu", (unsigned long)st->conflicts);
    if(st->neighbor.valid) {
        line(&l, "%s %s", st->neighbor.proto, st->neighbor.sys_name);
        line(&l, "Port %s", st->neighbor.port_id);
        if(st->neighbor.vlan) line(&l, "VLAN %u", st->neighbor.vlan);
    }
    line(&l, "MAC " MACF, MACA(st->mac));
    line(&l, "PHY setting: %s", app->settings.phy_mode == PhyAuto ? "auto" : "forced");
    app->scroll = MIN(app->scroll, MAX(0, l.line - l.visible));

    /* footer hint */
    canvas_draw_line(canvas, 0, 55, 127, 55);
    canvas_draw_str(canvas, 0, 63, app->settings.dhcp ? "OK: renew DHCP" : "OK: re-apply");
    if(l.line > l.visible) canvas_draw_str_aligned(canvas, 127, 63, AlignRight, AlignBottom, "^v");
}

static void draw_neighbors(Canvas* canvas, App* app) {
    NetState* st = &app->st;
    Neighbor* n = &st->neighbor;
    char a[16];
    draw_header(canvas, app, n->valid ? n->proto : NULL);
    Lines l = {canvas, app->scroll, 0, 6, TOP};
    uint32_t now = furi_get_tick();
    if(!n->valid) {
        line(&l, "No LLDP/CDP seen yet");
        line(&l, "(switch sends every 30-60s)");
    } else {
        bool stale = n->ttl && now - n->seen_tick > (uint32_t)n->ttl * 1000;
        line(&l, "%s%s", n->sys_name, stale ? " (old)" : "");
        line(&l, "Port: %s", n->port_id);
        if(n->port_desc[0]) line(&l, "Desc: %s", n->port_desc);
        if(n->vlan) line(&l, "VLAN (PVID): %u", n->vlan);
        if(n->voice_vlan) line(&l, "Voice VLAN: %u", n->voice_vlan);
        if(n->duplex[0]) {
            bool our_full = st->phy & PHY_DPX;
            bool their_full = strstr(n->duplex, "FD") || strstr(n->duplex, "full");
            bool their_half = strstr(n->duplex, "HD") || strstr(n->duplex, "half");
            bool mismatch = st->link && ((our_full && their_half) || (!our_full && their_full));
            line(&l, "Switch side: %s%s", n->duplex, mismatch ? " MISMATCH!" : "");
        }
        if(n->poe[0]) line(&l, "PoE: %s", n->poe);
        if(n->has_mgmt) line(&l, "Mgmt IP: " IPF, IPA(n->mgmt_ip));
        if(n->platform[0]) line(&l, "%s", n->platform);
        fmt_dur(a, sizeof(a), now - n->seen_tick);
        line(&l, "Seen %s ago", a);
    }
    if(st->stp.valid) {
        line(&l, "%s root prio %u", st->stp.rstp ? "RSTP" : "STP", st->stp.root_prio);
        line(&l, " " MACF, MACA(st->stp.root_mac));
        line(&l, "Cost %lu, bridge prio %u", (unsigned long)st->stp.root_cost, st->stp.bridge_prio);
    } else {
        line(&l, "No STP BPDUs seen");
    }
    if(st->vlan_count) {
        char v[40] = {0};
        size_t p = 0;
        for(uint8_t i = 0; i < st->vlan_count && p < sizeof(v) - 6; i++)
            p += snprintf(v + p, sizeof(v) - p, "%s%u", i ? "," : "", st->vlans[i]);
        line(&l, "Tagged VLANs: %s", v);
    }
    app->scroll = MIN(app->scroll, MAX(0, l.line - l.visible));
    if(l.line > l.visible) elements_scrollbar(canvas, app->scroll, l.line - l.visible + 1);
}

static void draw_ping(Canvas* canvas, App* app) {
    NetState* st = &app->st;
    uint8_t target[4];
    if(st->ping_running)
        memcpy(target, st->ping_ip, 4);
    else
        ping_target_resolve(app, target);
    draw_header(canvas, app, ping_preset_names[app->settings.ping_preset]);
    char buf[40];
    snprintf(buf, sizeof(buf), "> " IPF, IPA(target));
    canvas_draw_str(canvas, 0, 20, IP_ZERO(target) ? "> (no address yet)" : buf);
    if(st->ping_sent) {
        uint32_t loss = (st->ping_sent - st->ping_recv) * 100 / st->ping_sent;
        snprintf(
            buf,
            sizeof(buf),
            "%lu/%lu  loss %lu%%",
            (unsigned long)st->ping_recv,
            (unsigned long)st->ping_sent,
            (unsigned long)loss);
        canvas_draw_str(canvas, 0, 29, buf);
        if(st->ping_recv) {
            snprintf(
                buf,
                sizeof(buf),
                "min/avg/max %lu/%lu/%lu",
                (unsigned long)st->ping_min,
                (unsigned long)(st->ping_sum / st->ping_recv),
                (unsigned long)st->ping_max);
            canvas_draw_str(canvas, 0, 38, buf);
        }
    }
    canvas_draw_str_aligned(canvas, 127, 20, AlignRight, AlignBottom, st->ping_status);
    /* rtt graph: bars, lost = full-height x */
    const int gx = 0, gy = 40, gh = 13;
    uint8_t peak = 10;
    for(uint8_t i = 0; i < st->ping_hist_len; i++)
        if(st->ping_hist[i] != 255 && st->ping_hist[i] > peak) peak = st->ping_hist[i];
    for(uint8_t i = 0; i < st->ping_hist_len; i++) {
        int x = gx + i * 4;
        uint8_t v = st->ping_hist[i];
        if(v == 255) {
            canvas_draw_line(canvas, x, gy + 1, x + 2, gy + gh);
            canvas_draw_line(canvas, x + 2, gy + 1, x, gy + gh);
        } else {
            int h = 1 + (v * (gh - 1)) / peak;
            canvas_draw_box(canvas, x, gy + gh - h + 1, 3, h);
        }
    }
    canvas_draw_line(canvas, 0, 55, 127, 55);
    canvas_draw_str(canvas, 0, 63, st->ping_running ? "OK stop" : "OK start");
    canvas_draw_str_aligned(canvas, 127, 63, AlignRight, AlignBottom, "<edit  >target");
}

static void draw_dns(Canvas* canvas, App* app) {
    NetState* st = &app->st;
    draw_header(canvas, app, NULL);
    canvas_draw_str(canvas, 0, 21, app->settings.dns_name);
    char buf[40];
    snprintf(buf, sizeof(buf), "Server " IPF, IPA(st->dns));
    canvas_draw_str(canvas, 0, 31, IP_ZERO(st->dns) ? "Server 8.8.8.8 (no DHCP DNS)" : buf);
    canvas_set_font(canvas, FontPrimary);
    if(st->dns_busy) {
        canvas_draw_str(canvas, 0, 44, "...");
    } else if(st->dns_ok) {
        snprintf(buf, sizeof(buf), IPF, IPA(st->dns_result));
        canvas_draw_str(canvas, 0, 44, buf);
    }
    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str_aligned(canvas, 127, 44, AlignRight, AlignBottom, st->dns_status);
    canvas_draw_line(canvas, 0, 55, 127, 55);
    canvas_draw_str(canvas, 0, 63, "OK resolve");
    canvas_draw_str_aligned(canvas, 127, 63, AlignRight, AlignBottom, "< > edit name");
}

static void draw_arp(Canvas* canvas, App* app) {
    NetState* st = &app->st;
    char hdr[16];
    if(st->arp_busy)
        snprintf(hdr, sizeof(hdr), "%u/%u", st->arp_done, st->arp_total);
    else
        snprintf(hdr, sizeof(hdr), "%u found", st->arp_count);
    draw_header(canvas, app, hdr);
    Lines l = {canvas, app->scroll, 0, 6, TOP};
    if(!st->arp_count) {
        line(&l, st->arp_busy ? "Scanning..." : "OK: scan the subnet");
        line(&l, "Hosts heard by ARP are");
        line(&l, "added here passively too");
    }
    for(uint8_t i = 0; i < st->arp_count; i++) {
        const ArpHost* h = &st->arp[i];
        bool self = !memcmp(h->ip, st->ip, 4);
        bool gw = !memcmp(h->ip, st->gw, 4);
        line(
            &l,
            "%u.%u %02X%02X%02X%02X%02X%02X%s",
            h->ip[2],
            h->ip[3],
            MACA(h->mac),
            self ? " me" : gw ? " gw" : "");
    }
    app->scroll = MIN(app->scroll, MAX(0, l.line - l.visible));
    if(l.line > l.visible) elements_scrollbar(canvas, app->scroll, l.line - l.visible + 1);
}

static void draw_dhcp(Canvas* canvas, App* app) {
    NetState* st = &app->st;
    draw_header(canvas, app, st->dhcps_busy ? "scanning" : NULL);
    Lines l = {canvas, app->scroll, 0, 6, TOP};
    if(!st->dhcps_done && !st->dhcps_busy) {
        line(&l, "OK: send DHCP DISCOVER and");
        line(&l, "list every server that");
        line(&l, "answers (finds rogue DHCP).");
        line(&l, "No address is taken.");
    } else if(!st->dhcps_count) {
        line(&l, st->dhcps_busy ? "Waiting for offers..." : "No DHCP server answered");
    } else if(st->dhcps_count > 1 && !st->dhcps_busy) {
        line(&l, "%u SERVERS - possible rogue!", st->dhcps_count);
    }
    for(uint8_t i = 0; i < st->dhcps_count; i++) {
        DhcpServer* d = &st->dhcps[i];
        line(&l, "#%u server " IPF, i + 1, IPA(d->server));
        line(&l, " offer " IPF, IPA(d->offered));
        line(&l, " gw " IPF " %lus", IPA(d->router), (unsigned long)d->lease);
    }
    app->scroll = MIN(app->scroll, MAX(0, l.line - l.visible));
    if(l.line > l.visible) elements_scrollbar(canvas, app->scroll, l.line - l.visible + 1);
}

static void draw_traffic(Canvas* canvas, App* app) {
    NetState* st = &app->st;
    char a[12], b[12];
    draw_header(canvas, app, NULL);
    Lines l = {canvas, app->scroll, 0, 6, TOP};
    fmt_count(a, sizeof(a), st->rx_frames);
    fmt_count(b, sizeof(b), st->rx_bytes);
    line(&l, "Frames %s  bytes %s", a, b);
    line(&l, "Now %lu/s  peak %lu/s", (unsigned long)st->pps, (unsigned long)st->pps_peak);
    fmt_count(a, sizeof(a), st->rx_bcast);
    fmt_count(b, sizeof(b), st->rx_mcast);
    line(&l, "Bcast %s (%lu/s)  mcast %s", a, (unsigned long)st->bcast_pps, b);
    fmt_count(a, sizeof(a), st->rx_arp);
    fmt_count(b, sizeof(b), st->rx_ipv4);
    line(&l, "ARP %s  IPv4 %s", a, b);
    fmt_count(a, sizeof(a), st->rx_ipv6);
    fmt_count(b, sizeof(b), st->rx_other);
    line(&l, "IPv6 %s  other %s", a, b);
    fmt_count(a, sizeof(a), st->rx_tagged);
    line(&l, "802.1Q tagged: %s", a);
    line(&l, "Link up %lu, down %lu times", (unsigned long)st->link_ups, (unsigned long)st->link_downs);
    line(&l, "(frames to other hosts are");
    line(&l, " not visible on a switch)");
    line(&l, "OK: reset counters");
    app->scroll = MIN(app->scroll, MAX(0, l.line - l.visible));
    if(l.line > l.visible) elements_scrollbar(canvas, app->scroll, l.line - l.visible + 1);
}

static void draw_log(Canvas* canvas, App* app) {
    NetState* st = &app->st;
    char hdr[16];
    snprintf(hdr, sizeof(hdr), "%u", st->log_count);
    draw_header(canvas, app, hdr);
    const int16_t visible = 6;
    int16_t max_scroll = MAX(0, (int16_t)st->log_count - visible);
    /* scroll counts from the newest line upward */
    if(app->scroll > max_scroll) app->scroll = max_scroll;
    for(int16_t row = 0; row < visible; row++) {
        int16_t idx_from_end = app->scroll + (visible - 1 - row);
        if(idx_from_end >= st->log_count) continue;
        int16_t idx = (int16_t)(st->log_head + LOG_LINES - 1 - idx_from_end) % LOG_LINES;
        canvas_draw_str(canvas, 0, TOP + LINE_H * (row + 1) - 1, st->log[idx]);
    }
    if(max_scroll) elements_scrollbar(canvas, max_scroll - app->scroll, max_scroll + 1);
}

static void draw_wol(Canvas* canvas, App* app) {
    draw_header(canvas, app, NULL);
    char buf[32];
    snprintf(buf, sizeof(buf), MACF, MACA(app->settings.wol_mac));
    canvas_draw_str(canvas, 0, 22, "Target MAC:");
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 0, 34, buf);
    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str(canvas, 0, 45, app->st.wol_status);
    canvas_draw_line(canvas, 0, 55, 127, 55);
    canvas_draw_str(canvas, 0, 63, "OK send");
    canvas_draw_str_aligned(canvas, 127, 63, AlignRight, AlignBottom, "< > edit MAC");
}

static void draw_about(Canvas* canvas, App* app) {
    draw_header(canvas, app, "W5500");
    Lines l = {canvas, app->scroll, 0, 6, TOP};
    line(&l, "W5500    Flipper GPIO");
    line(&l, "MOSI  -> A7  (pin 2)");
    line(&l, "MISO  -> A6  (pin 3)");
    line(&l, "CS/nSS-> A4  (pin 4)");
    line(&l, "SCK   -> B3  (pin 5)");
    line(&l, "RST   -> C3  (pin 7)");
    line(&l, "GND   -> GND (pin 8/11)");
    line(&l, "3V3   -> 3V3 (pin 9)");
    line(&l, "5V modules: pin 1,");
    line(&l, " enable 5V in Settings");
    line(&l, "Logs: SD/apps_data/");
    line(&l, " rj45_tester/log.txt");
    app->scroll = MIN(app->scroll, MAX(0, l.line - l.visible));
    if(l.line > l.visible) elements_scrollbar(canvas, app->scroll, l.line - l.visible + 1);
}

void screen_draw(Canvas* canvas, void* model) {
    App* app = ((ScreenModel*)model)->app;
    canvas_clear(canvas);
    canvas_set_color(canvas, ColorBlack);
    furi_mutex_acquire(app->mutex, FuriWaitForever);
    switch(app->screen) {
    case ScreenStatus:
        draw_status(canvas, app);
        break;
    case ScreenNeighbors:
        draw_neighbors(canvas, app);
        break;
    case ScreenPing:
        draw_ping(canvas, app);
        break;
    case ScreenDns:
        draw_dns(canvas, app);
        break;
    case ScreenArp:
        draw_arp(canvas, app);
        break;
    case ScreenDhcp:
        draw_dhcp(canvas, app);
        break;
    case ScreenTraffic:
        draw_traffic(canvas, app);
        break;
    case ScreenLog:
        draw_log(canvas, app);
        break;
    case ScreenWol:
        draw_wol(canvas, app);
        break;
    case ScreenAbout:
        draw_about(canvas, app);
        break;
    }
    furi_mutex_release(app->mutex);
}
