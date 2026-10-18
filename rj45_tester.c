#include "rj45_tester.h"

#include <furi_hal.h>

static void switch_to(App* app, ViewId id) {
    app->current = id;
    view_dispatcher_switch_to_view(app->view_dispatcher, id);
}

/* ---------- editors ---------- */

static void byte_input_done(void* ctx) {
    App* app = ctx;
    memcpy(app->edit_target, app->edit_buf, app->edit_len);
    settings_save(app);
    if(app->edit_return == ViewSettings) {
        app->settings_dirty = true;
        settings_view_rebuild(app);
    }
    switch_to(app, app->edit_return);
}

static void edit_bytes(App* app, const char* title, uint8_t* target, size_t n, ViewId back) {
    app->edit_target = target;
    app->edit_return = back;
    app->edit_len = n;
    memcpy(app->edit_buf, target, n);
    byte_input_set_header_text(app->byte_input, title);
    byte_input_set_result_callback(app->byte_input, byte_input_done, NULL, app, app->edit_buf, n);
    switch_to(app, ViewByteInput);
}

static void text_input_done(void* ctx) {
    App* app = ctx;
    strlcpy(app->settings.dns_name, app->text_buf, sizeof(app->settings.dns_name));
    settings_save(app);
    switch_to(app, ViewScreen);
}

static void edit_dns_name(App* app) {
    strlcpy(app->text_buf, app->settings.dns_name, sizeof(app->text_buf));
    text_input_reset(app->text_input);
    text_input_set_header_text(app->text_input, "Host name");
    text_input_set_result_callback(
        app->text_input, text_input_done, app, app->text_buf, sizeof(app->text_buf), false);
    switch_to(app, ViewTextInput);
}

/* ---------- screen input ---------- */

bool screen_input(InputEvent* event, void* ctx) {
    App* app = ctx;
    if(event->type != InputTypeShort && event->type != InputTypeRepeat) return false;
    if(event->key == InputKeyBack) return false;
    NetState* st = &app->st;

    if(event->key == InputKeyUp || event->key == InputKeyDown) {
        int16_t step = event->type == InputTypeRepeat ? 3 : 1;
        bool older = event->key == InputKeyUp;
        if(app->screen == ScreenLog) {
            app->scroll += older ? step : -step;
        } else {
            app->scroll += older ? -step : step;
        }
        if(app->scroll < 0) app->scroll = 0;
        return true;
    }
    if(event->type != InputTypeShort) return true;

    switch(app->screen) {
    case ScreenStatus:
        if(event->key == InputKeyOk) worker_signal(app, app->settings.dhcp ? WF_DHCP : WF_APPLY);
        break;
    case ScreenPing:
        if(event->key == InputKeyOk) {
            worker_signal(app, st->ping_running ? WF_PING_STOP : WF_PING);
        } else if(event->key == InputKeyRight && !st->ping_running) {
            app->settings.ping_preset = (app->settings.ping_preset + 1) % PING_PRESETS;
            settings_save(app);
        } else if(event->key == InputKeyLeft && !st->ping_running) {
            app->settings.ping_preset = PING_PRESETS - 1;
            edit_bytes(app, "Ping target IP", app->settings.ping_custom, 4, ViewScreen);
        }
        break;
    case ScreenDns:
        if(event->key == InputKeyOk && !st->dns_busy)
            worker_signal(app, WF_DNS);
        else if(event->key == InputKeyLeft || event->key == InputKeyRight)
            edit_dns_name(app);
        break;
    case ScreenArp:
        if(event->key == InputKeyOk && !st->arp_busy) worker_signal(app, WF_ARP);
        break;
    case ScreenDhcp:
        if(event->key == InputKeyOk && !st->dhcps_busy) worker_signal(app, WF_DHCPSCAN);
        break;
    case ScreenTraffic:
    case ScreenNeighbors:
        if(event->key == InputKeyOk) worker_signal(app, WF_CLEAR);
        break;
    case ScreenWol:
        if(event->key == InputKeyOk)
            worker_signal(app, WF_WOL);
        else if(event->key == InputKeyLeft || event->key == InputKeyRight)
            edit_bytes(app, "Target MAC", app->settings.wol_mac, 6, ViewScreen);
        break;
    default:
        break;
    }
    return true;
}

/* ---------- settings ---------- */

enum {
    SetAddr,
    SetIp,
    SetMask,
    SetGw,
    SetDns,
    SetPhy,
    SetMac,
    SetCustomMac,
    SetSound,
    SetVibro,
    SetOtg,
    SetLogSd,
};

static const char* const off_on[] = {"Off", "On"};
static const char* const phy_names[PhyModeCount] = {"Auto", "100 Full", "100 Half", "10 Full", "10 Half"};
static const char* const mac_names[] = {"Device", "Random", "Custom"};

static void set_otg(App* app, bool on) {
    if(on && !furi_hal_power_is_otg_enabled()) {
        app->otg_enabled_by_us = furi_hal_power_enable_otg();
    } else if(!on && app->otg_enabled_by_us) {
        furi_hal_power_disable_otg();
        app->otg_enabled_by_us = false;
    }
}

static void settings_changed(VariableItem* item) {
    App* app = variable_item_get_context(item);
    uint8_t idx = variable_item_get_current_value_index(item);
    uint8_t sel = variable_item_list_get_selected_item_index(app->settings_list);
    Settings* s = &app->settings;
    switch(sel) {
    case SetAddr:
        s->dhcp = idx == 0;
        variable_item_set_current_value_text(item, s->dhcp ? "DHCP" : "Static");
        app->settings_dirty = true;
        break;
    case SetPhy:
        s->phy_mode = idx;
        variable_item_set_current_value_text(item, phy_names[idx]);
        app->settings_dirty = true;
        break;
    case SetMac:
        s->mac_mode = idx;
        variable_item_set_current_value_text(item, mac_names[idx]);
        app->settings_dirty = true;
        break;
    case SetSound:
        s->sound = idx;
        variable_item_set_current_value_text(item, off_on[idx]);
        break;
    case SetVibro:
        s->vibro = idx;
        variable_item_set_current_value_text(item, off_on[idx]);
        break;
    case SetOtg:
        s->otg = idx;
        variable_item_set_current_value_text(item, off_on[idx]);
        set_otg(app, s->otg);
        break;
    case SetLogSd:
        s->log_sd = idx;
        variable_item_set_current_value_text(item, off_on[idx]);
        break;
    }
    settings_save(app);
}

static void settings_enter(void* ctx, uint32_t index) {
    App* app = ctx;
    Settings* s = &app->settings;
    switch(index) {
    case SetIp:
        edit_bytes(app, "Static IP", s->ip, 4, ViewSettings);
        break;
    case SetMask:
        edit_bytes(app, "Subnet mask", s->mask, 4, ViewSettings);
        break;
    case SetGw:
        edit_bytes(app, "Gateway", s->gw, 4, ViewSettings);
        break;
    case SetDns:
        edit_bytes(app, "DNS server", s->dns, 4, ViewSettings);
        break;
    case SetCustomMac:
        edit_bytes(app, "Custom MAC", s->custom_mac, 6, ViewSettings);
        break;
    }
}

static VariableItem* add_item(App* app, const char* label, uint8_t count, uint8_t idx, const char* text) {
    VariableItem* it = variable_item_list_add(app->settings_list, label, count, settings_changed, app);
    variable_item_set_current_value_index(it, idx);
    variable_item_set_current_value_text(it, text);
    return it;
}

void settings_view_rebuild(App* app) {
    Settings* s = &app->settings;
    uint8_t sel = variable_item_list_get_selected_item_index(app->settings_list);
    variable_item_list_reset(app->settings_list);
    char buf[24];
    add_item(app, "Address", 2, s->dhcp ? 0 : 1, s->dhcp ? "DHCP" : "Static");
    snprintf(buf, sizeof(buf), IPF, IPA(s->ip));
    add_item(app, "IP", 1, 0, buf);
    snprintf(buf, sizeof(buf), IPF, IPA(s->mask));
    add_item(app, "Mask", 1, 0, buf);
    snprintf(buf, sizeof(buf), IPF, IPA(s->gw));
    add_item(app, "Gateway", 1, 0, buf);
    snprintf(buf, sizeof(buf), IPF, IPA(s->dns));
    add_item(app, "DNS", 1, 0, buf);
    add_item(app, "Link mode", PhyModeCount, s->phy_mode, phy_names[s->phy_mode]);
    add_item(app, "MAC", 3, s->mac_mode, mac_names[s->mac_mode]);
    snprintf(buf, sizeof(buf), "%02X%02X%02X%02X%02X%02X", MACA(s->custom_mac));
    add_item(app, "Custom MAC", 1, 0, buf);
    add_item(app, "Sound", 2, s->sound, off_on[s->sound]);
    add_item(app, "Vibro", 2, s->vibro, off_on[s->vibro]);
    add_item(app, "5V on pin 1", 2, s->otg, off_on[s->otg]);
    add_item(app, "Log to SD", 2, s->log_sd, off_on[s->log_sd]);
    variable_item_list_set_enter_callback(app->settings_list, settings_enter, app);
    variable_item_list_set_selected_item(app->settings_list, sel);
}

/* ---------- menu & navigation ---------- */

enum {
    MenuStatus,
    MenuNeighbors,
    MenuPing,
    MenuDns,
    MenuArp,
    MenuDhcp,
    MenuTraffic,
    MenuLog,
    MenuWol,
    MenuSettings,
    MenuAbout,
};

static void menu_callback(void* ctx, uint32_t index) {
    App* app = ctx;
    static const Screen screens[] = {
        ScreenStatus,
        ScreenNeighbors,
        ScreenPing,
        ScreenDns,
        ScreenArp,
        ScreenDhcp,
        ScreenTraffic,
        ScreenLog,
        ScreenWol,
    };
    if(index == MenuSettings) {
        app->settings_dirty = false;
        settings_view_rebuild(app);
        switch_to(app, ViewSettings);
        return;
    }
    app->screen = index == MenuAbout ? ScreenAbout : screens[index];
    app->scroll = 0;
    switch_to(app, ViewScreen);
}

static bool navigation_callback(void* ctx) {
    App* app = ctx;
    switch(app->current) {
    case ViewMenu:
        return false;
    case ViewSettings:
        settings_save(app);
        if(app->settings_dirty) worker_signal(app, WF_APPLY);
        app->settings_dirty = false;
        switch_to(app, ViewMenu);
        return true;
    case ViewByteInput:
    case ViewTextInput:
        switch_to(app, app->edit_return == ViewSettings ? ViewSettings : ViewScreen);
        return true;
    default:
        switch_to(app, ViewMenu);
        return true;
    }
}

static void redraw_timer(void* ctx) {
    App* app = ctx;
    if(app->current == ViewScreen) {
        with_view_model(app->screen_view, ScreenModel * m, { UNUSED(m); }, true);
    }
}

/* ---------- lifecycle ---------- */

static App* app_alloc(void) {
    App* app = malloc(sizeof(App));
    memset(app, 0, sizeof(App));
    app->mutex = furi_mutex_alloc(FuriMutexTypeNormal);
    app->gui = furi_record_open(RECORD_GUI);
    app->notifications = furi_record_open(RECORD_NOTIFICATION);
    app->storage = furi_record_open(RECORD_STORAGE);
    settings_load(app);
    app->st.session_tick = furi_get_tick();
    app->st.link_change_tick = furi_get_tick();

    app->view_dispatcher = view_dispatcher_alloc();
    view_dispatcher_set_event_callback_context(app->view_dispatcher, app);
    view_dispatcher_set_navigation_event_callback(app->view_dispatcher, navigation_callback);
    view_dispatcher_attach_to_gui(app->view_dispatcher, app->gui, ViewDispatcherTypeFullscreen);

    app->menu = submenu_alloc();
    submenu_set_header(app->menu, "RJ45 Tester (W5500)");
    submenu_add_item(app->menu, "Link status", MenuStatus, menu_callback, app);
    submenu_add_item(app->menu, "Switch / LLDP / CDP", MenuNeighbors, menu_callback, app);
    submenu_add_item(app->menu, "Ping", MenuPing, menu_callback, app);
    submenu_add_item(app->menu, "DNS lookup", MenuDns, menu_callback, app);
    submenu_add_item(app->menu, "Hosts (ARP scan)", MenuArp, menu_callback, app);
    submenu_add_item(app->menu, "DHCP servers", MenuDhcp, menu_callback, app);
    submenu_add_item(app->menu, "Traffic", MenuTraffic, menu_callback, app);
    submenu_add_item(app->menu, "Event log", MenuLog, menu_callback, app);
    submenu_add_item(app->menu, "Wake-on-LAN", MenuWol, menu_callback, app);
    submenu_add_item(app->menu, "Settings", MenuSettings, menu_callback, app);
    submenu_add_item(app->menu, "Wiring", MenuAbout, menu_callback, app);
    view_dispatcher_add_view(app->view_dispatcher, ViewMenu, submenu_get_view(app->menu));

    app->screen_view = view_alloc();
    view_allocate_model(app->screen_view, ViewModelTypeLocking, sizeof(ScreenModel));
    with_view_model(app->screen_view, ScreenModel * m, { m->app = app; }, false);
    view_set_context(app->screen_view, app);
    view_set_draw_callback(app->screen_view, screen_draw);
    view_set_input_callback(app->screen_view, screen_input);
    view_dispatcher_add_view(app->view_dispatcher, ViewScreen, app->screen_view);

    app->settings_list = variable_item_list_alloc();
    view_dispatcher_add_view(
        app->view_dispatcher, ViewSettings, variable_item_list_get_view(app->settings_list));

    app->byte_input = byte_input_alloc();
    view_dispatcher_add_view(app->view_dispatcher, ViewByteInput, byte_input_get_view(app->byte_input));

    app->text_input = text_input_alloc();
    view_dispatcher_add_view(app->view_dispatcher, ViewTextInput, text_input_get_view(app->text_input));

    app->redraw_timer = furi_timer_alloc(redraw_timer, FuriTimerTypePeriodic, app);

    app->worker = furi_thread_alloc_ex("Rj45Worker", 4096, worker_thread, app);
    return app;
}

static void app_free(App* app) {
    furi_timer_stop(app->redraw_timer);
    furi_timer_free(app->redraw_timer);

    view_dispatcher_remove_view(app->view_dispatcher, ViewMenu);
    view_dispatcher_remove_view(app->view_dispatcher, ViewScreen);
    view_dispatcher_remove_view(app->view_dispatcher, ViewSettings);
    view_dispatcher_remove_view(app->view_dispatcher, ViewByteInput);
    view_dispatcher_remove_view(app->view_dispatcher, ViewTextInput);
    submenu_free(app->menu);
    view_free(app->screen_view);
    variable_item_list_free(app->settings_list);
    byte_input_free(app->byte_input);
    text_input_free(app->text_input);
    view_dispatcher_free(app->view_dispatcher);

    furi_record_close(RECORD_STORAGE);
    furi_record_close(RECORD_NOTIFICATION);
    furi_record_close(RECORD_GUI);
    furi_mutex_free(app->mutex);
    free(app);
}

int32_t rj45_tester_app(void* p) {
    UNUSED(p);
    App* app = app_alloc();
    if(app->settings.otg) set_otg(app, true);

    furi_thread_start(app->worker);
    furi_timer_start(app->redraw_timer, furi_ms_to_ticks(200));

    app->screen = ScreenStatus;
    switch_to(app, ViewScreen);
    view_dispatcher_run(app->view_dispatcher);

    worker_signal(app, WF_EXIT);
    furi_thread_join(app->worker);
    furi_thread_free(app->worker);
    set_otg(app, false);
    app_free(app);
    return 0;
}
