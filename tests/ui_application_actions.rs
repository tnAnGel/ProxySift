use i_slint_backend_testing::ElementHandle;
use proxy_sift::app::{AppWindow, ProxyRow};
use slint::{platform::PointerEventButton, ComponentHandle, ModelRc, SharedString, VecModel};
use std::{cell::RefCell, rc::Rc};

async fn click(app: &AppWindow, id: &str) {
    click_nth(app, id, 0).await;
}

async fn click_nth(app: &AppWindow, id: &str, index: usize) {
    let elements: Vec<_> = ElementHandle::find_by_element_id(app, id).collect();
    assert!(
        index < elements.len(),
        "Slint element {id} at index {index} not found ({} matches)",
        elements.len()
    );
    elements[index].single_click(PointerEventButton::Left).await;
}

fn record(events: &Rc<RefCell<Vec<String>>>, value: impl Into<String>) {
    events.borrow_mut().push(value.into());
}

#[test]
fn visible_screen_actions_reach_their_state_or_callback() {
    i_slint_backend_testing::init_integration_test_with_system_time();

    slint::spawn_local(async move {
        let app = AppWindow::new().unwrap();
        let events = Rc::new(RefCell::new(Vec::<String>::new()));
        let weak_app = app.as_weak();

        app.on_start_check({
            let e = events.clone();
            move || record(&e, "start-check")
        });
        app.on_cancel_check({
            let e = events.clone();
            move || record(&e, "cancel-check")
        });
        app.on_filter_results({
            let e = events.clone();
            move || record(&e, "filter-results")
        });
        app.on_sort_results({
            let e = events.clone();
            let ui = weak_app.clone();
            move |v| {
                record(&e, format!("sort:{}", v));
                if let Some(ui) = ui.upgrade() {
                    if ui.get_result_sort_column() == v {
                        ui.set_result_sort_descending(!ui.get_result_sort_descending());
                    } else {
                        ui.set_result_sort_column(v);
                        ui.set_result_sort_descending(true);
                    }
                    ui.invoke_filter_results();
                }
            }
        });
        app.on_select_result_filter({
            let e = events.clone();
            let ui = weak_app.clone();
            move |v| {
                record(&e, format!("result-filter:{}", v));
                if let Some(ui) = ui.upgrade() {
                    ui.set_result_filter(v);
                    ui.invoke_filter_results();
                }
            }
        });
        app.on_export_results({
            let e = events.clone();
            move || record(&e, "export")
        });
        app.on_copy_proxy_address({
            let e = events.clone();
            move |v| record(&e, format!("copy:{}", v))
        });
        app.on_open_results_folder({
            let e = events.clone();
            move || record(&e, "results-folder")
        });
        app.on_minimize_window({
            let e = events.clone();
            let ui = weak_app.clone();
            move || {
                record(&e, "minimize");
                if let Some(ui) = ui.upgrade() {
                    ui.window().set_minimized(true);
                }
            }
        });
        app.on_toggle_maximize_window({
            let e = events.clone();
            let ui = weak_app.clone();
            move || {
                record(&e, "maximize");
                if let Some(ui) = ui.upgrade() {
                    let window = ui.window();
                    window.set_maximized(!window.is_maximized());
                }
            }
        });
        app.on_subscriptions_changed({
            let e = events.clone();
            move || record(&e, "subscriptions-changed")
        });
        app.on_preferences_changed({
            let e = events.clone();
            move || record(&e, "preferences-changed")
        });
        app.on_select_source_set({
            let e = events.clone();
            let ui = weak_app.clone();
            move |v| {
                record(&e, format!("source-set:{}", v));
                if let Some(ui) = ui.upgrade() {
                    ui.set_source_set(v);
                }
            }
        });
        app.on_select_checker_mode({
            let e = events.clone();
            let ui = weak_app.clone();
            move |v| {
                record(&e, format!("checker-mode:{}", v));
                if let Some(ui) = ui.upgrade() {
                    ui.set_checker_mode(v);
                    ui.set_result_filter("Все".into());
                }
            }
        });
        app.on_add_catalog_entry({
            let e = events.clone();
            let ui = weak_app.clone();
            move |v| {
                record(&e, format!("add-source:{}", v));
                if let Some(ui) = ui.upgrade() {
                    if v.starts_with("https://") || v.starts_with("http://") {
                        ui.set_catalog_editor_error(SharedString::default());
                        ui.set_show_catalog_editor(false);
                    } else {
                        ui.set_catalog_editor_error(
                            "Введите корректную ссылку с адресом источника.".into(),
                        );
                    }
                }
            }
        });
        app.on_remove_catalog_entry({
            let e = events.clone();
            move |v| record(&e, format!("remove-source:{v}"))
        });
        app.on_open_app_data_directory({
            let e = events.clone();
            move || record(&e, "app-data-folder")
        });
        app.on_refresh_runtime_status({
            let e = events.clone();
            move || record(&e, "runtime-refresh")
        });
        app.on_manage_core({
            let e = events.clone();
            move || record(&e, "manage-core")
        });
        app.on_manage_geoip({
            let e = events.clone();
            move || record(&e, "manage-geoip")
        });
        app.on_load_database({
            let e = events.clone();
            move |vpn| record(&e, format!("load-database:{vpn}"))
        });
        app.on_database_search_changed({
            let e = events.clone();
            let ui = weak_app.clone();
            move |vpn, query| {
                record(&e, format!("database-search:{vpn}:{query}"));
                if let Some(ui) = ui.upgrade() {
                    ui.set_database_query(query);
                }
            }
        });
        app.on_database_page_changed({
            let e = events.clone();
            move |vpn, direction| record(&e, format!("database-page:{vpn}:{direction}"))
        });

        app.show().unwrap();

        // Sidebar destinations and overview shortcuts.
        click(&app, "AppWindow::overview-nav-item").await;
        assert_eq!(app.get_active_page().as_str(), "overview");
        click(&app, "OverviewScreen::overview-new-check").await;
        assert_eq!(app.get_active_page().as_str(), "check");
        click(&app, "AppWindow::overview-nav-item").await;
        click(&app, "OverviewScreen::overview-status-history").await;
        assert_eq!(app.get_active_page().as_str(), "history");
        click(&app, "AppWindow::overview-nav-item").await;
        click(&app, "OverviewScreen::overview-all-history").await;
        assert_eq!(app.get_active_page().as_str(), "history");
        click(&app, "AppWindow::overview-nav-item").await;
        click(&app, "OverviewScreen::overview-manage-sources").await;
        assert_eq!(app.get_active_page().as_str(), "sources");
        click(&app, "AppWindow::overview-nav-item").await;
        click(&app, "OverviewScreen::overview-open-runtime").await;
        assert_eq!(app.get_active_page().as_str(), "runtime");

        // Catalog, subscriptions, manual proxy links, and their editors.
        click(&app, "AppWindow::sources-nav-item").await;
        app.set_catalog_entries(ModelRc::new(VecModel::from(vec![
            SharedString::from("https://one.example/proxies.txt"),
            SharedString::from("https://two.example/proxies.txt"),
        ])));
        assert!(app.get_use_default_sources());
        click(&app, "SourcesScreen::sources-toggle-catalog").await;
        assert!(!app.get_use_default_sources());
        click(&app, "SourcesScreen::sources-toggle-catalog").await;
        assert!(app.get_use_default_sources());
        click(&app, "SourcesScreen::remove-entry-area").await;
        assert!(events.borrow().contains(&"remove-source:0".to_string()));

        click(&app, "SourcesScreen::sources-add-source").await;
        assert!(app.get_show_catalog_editor());
        app.set_draft_catalog_url("not a URL".into());
        click(&app, "AppWindow::save-catalog-editor-area").await;
        assert!(app.get_show_catalog_editor());
        assert!(!app.get_catalog_editor_error().is_empty());
        click(&app, "AppWindow::close-catalog-editor-area").await;
        assert!(!app.get_show_catalog_editor());
        click(&app, "SourcesScreen::sources-add-source").await;
        assert!(app.get_show_catalog_editor());
        app.set_draft_catalog_url("https://new.example/proxies.txt".into());
        click(&app, "AppWindow::save-catalog-editor-area").await;
        assert!(events
            .borrow()
            .contains(&"add-source:https://new.example/proxies.txt".to_string()));
        assert!(!app.get_show_catalog_editor());
        click(&app, "SourcesScreen::sources-add-source").await;
        click(&app, "AppWindow::cancel-catalog-editor-area").await;
        assert!(!app.get_show_catalog_editor());

        click(&app, "SourcesScreen::sources-edit-subscriptions").await;
        assert!(app.get_show_source_editor());
        app.set_draft_subscriptions("https://sub.example/list".into());
        app.set_draft_proxy_links("vless://node@example.com:443".into());
        click(&app, "AppWindow::save-editor-area").await;
        assert_eq!(app.get_subscriptions().as_str(), "https://sub.example/list");
        assert_eq!(
            app.get_proxy_links().as_str(),
            "vless://node@example.com:443"
        );
        assert!(events
            .borrow()
            .contains(&"subscriptions-changed".to_string()));
        assert!(!app.get_show_source_editor());

        click(&app, "SourcesScreen::sources-edit-proxy-links").await;
        assert!(app.get_show_source_editor());
        click(&app, "AppWindow::cancel-editor-area").await;
        assert!(!app.get_show_source_editor());
        click(&app, "SourcesScreen::sources-start-check").await;
        assert_eq!(app.get_active_page().as_str(), "check");

        // History and both archive pages, including search and pagination actions.
        click(&app, "AppWindow::history-nav-item").await;
        click(&app, "HistoryScreen::history-first-check").await;
        assert_eq!(app.get_active_page().as_str(), "check");
        click(&app, "AppWindow::history-nav-item").await;
        click(&app, "HistoryScreen::history-new-check").await;
        assert_eq!(app.get_active_page().as_str(), "check");
        click(&app, "AppWindow::proxy-db-nav-item").await;
        assert!(events.borrow().contains(&"load-database:false".to_string()));
        app.set_database_has_previous(true);
        app.set_database_has_next(true);
        click(&app, "ArchiveScreen::next-area").await;
        click(&app, "ArchiveScreen::prev-area").await;
        assert!(events
            .borrow()
            .contains(&"database-page:false:1".to_string()));
        assert!(events
            .borrow()
            .contains(&"database-page:false:-1".to_string()));
        let search = ElementHandle::find_by_element_id(&app, "ArchiveScreen::database-search")
            .next()
            .expect("database search input should be visible");
        search.set_accessible_value("198.51.100");
        assert!(events
            .borrow()
            .iter()
            .any(|event| event.starts_with("database-search:false:")));
        click(&app, "AppWindow::vpn-db-nav-item").await;
        assert!(events.borrow().contains(&"load-database:true".to_string()));
        let vpn_search = ElementHandle::find_by_element_id(&app, "ArchiveScreen::database-search")
            .next()
            .expect("VPN database search input should be visible");
        vpn_search.set_accessible_value("vless");
        assert!(events
            .borrow()
            .iter()
            .any(|event| event.starts_with("database-search:true:")));

        // Each preset applies its values and routes back to the launch form.
        for (index, expected_limit) in [(0, "100"), (1, "200"), (2, "500")] {
            click(&app, "AppWindow::profiles-nav-item").await;
            click_nth(&app, "ProfilePreset::preset-apply", index).await;
            assert_eq!(app.get_active_page().as_str(), "check");
            assert_eq!(app.get_limit_value().as_str(), expected_limit);
            if expected_limit == "100" {
                assert_eq!(app.get_threshold_value().as_str(), "0");
                assert!(!app.get_use_speed());
                assert!(!app.get_use_geoip());
            } else {
                assert_eq!(app.get_threshold_value().as_str(), "100");
                assert!(app.get_use_speed());
                assert!(app.get_use_geoip());
            }
        }
        click(&app, "AppWindow::profiles-nav-item").await;
        click(&app, "ProfilesScreen::profiles-return-to-check").await;
        assert_eq!(app.get_active_page().as_str(), "check");

        // Runtime actions are routed to host callbacks without starting downloads in the test.
        click(&app, "AppWindow::runtime-nav-item").await;
        click(&app, "RuntimeScreen::runtime-refresh").await;
        app.set_runtime_busy(true);
        click(&app, "ResourceStatusCard::resource-action").await;
        assert!(!events.borrow().contains(&"manage-core".to_string()));
        click(&app, "RuntimeScreen::runtime-refresh").await;
        assert_eq!(
            events
                .borrow()
                .iter()
                .filter(|event| *event == "runtime-refresh")
                .count(),
            2
        );
        app.set_runtime_busy(false);
        click_nth(&app, "ResourceStatusCard::resource-action", 0).await;
        click_nth(&app, "ResourceStatusCard::resource-action", 1).await;
        click(&app, "RuntimeScreen::runtime-open-data-folder").await;
        for expected in [
            "runtime-refresh",
            "manage-core",
            "manage-geoip",
            "app-data-folder",
        ] {
            assert!(
                events.borrow().contains(&expected.to_string()),
                "missing callback {expected}"
            );
        }

        // Main checker controls, filters, sorting, copying, export, and cancellation.
        click(&app, "AppWindow::check-nav-item").await;
        assert_eq!(app.get_active_page().as_str(), "check");
        click(&app, "AppWindow::edit-subscriptions-area").await;
        assert!(app.get_show_source_editor());
        click(&app, "AppWindow::close-editor-area").await;
        assert!(!app.get_show_source_editor());

        let number_fields: Vec<_> =
            ElementHandle::find_by_element_id(&app, "NumberField::number-input").collect();
        assert_eq!(number_fields.len(), 2);
        number_fields[0].set_accessible_value("125");
        number_fields[1].set_accessible_value("75");
        assert_eq!(app.get_limit_value().as_str(), "125");
        assert_eq!(app.get_threshold_value().as_str(), "75");

        for (option_id, expected_set) in [
            ("AppWindow::source-set-1-option", "1"),
            ("AppWindow::source-set-2-option", "2"),
            ("AppWindow::source-set-3-option", "3"),
        ] {
            click(&app, "AppWindow::source-set-area").await;
            click(&app, option_id).await;
            assert_eq!(app.get_source_set().as_str(), expected_set);
            assert!(events
                .borrow()
                .contains(&format!("source-set:{expected_set}")));
        }

        click(&app, "AppWindow::all-results-tab").await;
        click(&app, "AppWindow::live-results-tab").await;
        click(&app, "AppWindow::fast-results-tab").await;
        click(&app, "AppWindow::dead-results-tab").await;
        assert!(events.borrow().contains(&"result-filter:Все".to_string()));
        assert!(events.borrow().contains(&"result-filter:Живые".to_string()));
        assert!(events
            .borrow()
            .contains(&"result-filter:Быстрые".to_string()));
        assert!(events
            .borrow()
            .contains(&"result-filter:Недоступные".to_string()));

        click(&app, "AppWindow::filter-area").await;
        click(&app, "AppWindow::all-filter-option").await;
        assert_eq!(app.get_result_filter().as_str(), "Все");
        click(&app, "AppWindow::filter-area").await;
        click(&app, "AppWindow::live-filter-option").await;
        assert_eq!(app.get_result_filter().as_str(), "Живые");
        click(&app, "AppWindow::filter-area").await;
        click(&app, "AppWindow::fast-filter-option").await;
        assert_eq!(app.get_result_filter().as_str(), "Быстрые");
        click(&app, "AppWindow::filter-area").await;
        click(&app, "AppWindow::dead-filter-option").await;
        assert_eq!(app.get_result_filter().as_str(), "Недоступные");

        click(&app, "UnitSelect::unit-area").await;
        assert_eq!(
            ElementHandle::find_by_element_id(&app, "FilterOption::option-area").count(),
            2
        );
        click_nth(&app, "FilterOption::option-area", 1).await;
        assert_eq!(app.get_threshold_unit().as_str(), "МБ/с");
        click(&app, "UnitSelect::unit-area").await;
        click_nth(&app, "FilterOption::option-area", 0).await;
        assert_eq!(app.get_threshold_unit().as_str(), "КБ/с");

        let result_search = ElementHandle::find_by_element_id(&app, "AppWindow::results-search")
            .next()
            .expect("result search input should be visible");
        result_search.set_accessible_value("198.51.100");
        assert_eq!(app.get_search_query().as_str(), "198.51.100");
        assert!(events.borrow().contains(&"filter-results".to_string()));

        for (column_id, column) in [
            ("AppWindow::status-column-header", "status"),
            ("AppWindow::node-column-header", "node"),
            ("AppWindow::protocol-column-header", "protocol"),
            ("AppWindow::country-column-header", "country"),
            ("AppWindow::ping-column-header", "ping"),
            ("AppWindow::speed-column-header", "speed"),
            ("AppWindow::source-column-header", "source"),
        ] {
            click(&app, column_id).await;
            assert!(events.borrow().contains(&format!("sort:{column}")));
        }
        click(&app, "AppWindow::results-export-area").await;
        assert!(events.borrow().contains(&"export".to_string()));

        app.set_proxy_rows(ModelRc::new(VecModel::from(vec![ProxyRow {
            status: "Доступен".into(),
            node: "198.51.100.7:443".into(),
            protocol: "VLESS".into(),
            country: "США".into(),
            flag: "🇺🇸".into(),
            ping: "45 мс".into(),
            speed: "900 КБ/с".into(),
            source: "Тестовый источник".into(),
        }])));
        click(&app, "AppWindow::copy-area").await;
        assert!(events
            .borrow()
            .contains(&"copy:198.51.100.7:443".to_string()));

        app.set_checker_mode("vpn".into());
        let toggles: Vec<_> =
            ElementHandle::find_by_element_id(&app, "SwitchToggle::toggle-area").collect();
        assert_eq!(toggles.len(), 2);
        toggles[0].single_click(PointerEventButton::Left).await;
        toggles[1].single_click(PointerEventButton::Left).await;
        assert!(!app.get_use_speed());
        assert!(!app.get_use_geoip());
        let source_toggle = ElementHandle::find_by_element_id(&app, "CheckToggle::toggle-area")
            .next()
            .expect("built-in source toggle should be visible");
        source_toggle.single_click(PointerEventButton::Left).await;
        assert!(!app.get_use_default_sources());

        click(&app, "CheckerModeSelector::forward-mode-area").await;
        assert_eq!(app.get_checker_mode().as_str(), "forward");
        assert_eq!(
            ElementHandle::find_by_element_id(&app, "AppWindow::forward-source-hint").count(),
            1
        );
        assert!(
            ElementHandle::find_by_element_id(&app, "AppWindow::source-set-picker")
                .next()
                .is_none()
        );
        assert!(
            ElementHandle::find_by_element_id(&app, "AppWindow::fast-results-tab")
                .next()
                .is_none()
        );
        assert_eq!(
            ElementHandle::find_by_element_id(&app, "SwitchToggle::toggle-area").count(),
            1
        );
        click(&app, "CheckerModeSelector::vpn-mode-area").await;
        assert_eq!(app.get_checker_mode().as_str(), "vpn");
        assert!(
            ElementHandle::find_by_element_id(&app, "AppWindow::forward-source-hint")
                .next()
                .is_none()
        );
        assert_eq!(
            ElementHandle::find_by_element_id(&app, "AppWindow::source-set-picker").count(),
            1
        );

        click(&app, "AppWindow::more-area").await;
        assert!(app.get_show_more_menu());
        click(&app, "AppWindow::more-menu-backdrop").await;
        assert!(!app.get_show_more_menu());
        click(&app, "AppWindow::more-area").await;
        assert!(app.get_show_more_menu());
        click(&app, "AppWindow::more-open-folder-option").await;
        assert!(!app.get_show_more_menu());
        assert!(events.borrow().contains(&"results-folder".to_string()));
        click(&app, "AppWindow::more-area").await;
        click(&app, "AppWindow::more-export-option").await;
        assert!(events.borrow().contains(&"export".to_string()));

        click(&app, "RunStatusPanel::folder-area").await;
        assert!(events.borrow().contains(&"results-folder".to_string()));
        click(&app, "AppWindow::run-area").await;
        app.set_checking(true);
        click(&app, "RunStatusPanel::cancel-area").await;
        assert!(events.borrow().contains(&"cancel-check".to_string()));
        app.set_checking(false);

        // The native title-bar actions are wired. Closing is last because it closes this test window.
        click(&app, "AppWindow::minimize-window-area").await;
        click(&app, "AppWindow::maximize-window-area").await;
        assert!(events.borrow().contains(&"minimize".to_string()));
        assert!(events.borrow().contains(&"maximize".to_string()));
        assert!(app.window().is_minimized());
        assert!(app.window().is_maximized());
        click(&app, "AppWindow::maximize-window-area").await;
        assert!(!app.window().is_maximized());
        click(&app, "AppWindow::close-window-area").await;

        slint::quit_event_loop().unwrap();
    })
    .unwrap();

    slint::run_event_loop().unwrap();
}
