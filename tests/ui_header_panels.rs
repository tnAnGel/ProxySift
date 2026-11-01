use i_slint_backend_testing::ElementHandle;
use proxy_sift::app::AppWindow;
use slint::{platform::PointerEventButton, ComponentHandle};
use std::cell::Cell;
use std::rc::Rc;

async fn click(app: &AppWindow, element_id: &str) {
    let mut elements = ElementHandle::find_by_element_id(app, element_id);
    let element = elements
        .next()
        .unwrap_or_else(|| panic!("Slint element not found: {element_id}"));
    assert!(
        elements.next().is_none(),
        "Slint element id is ambiguous: {element_id}"
    );
    element.single_click(PointerEventButton::Left).await;
}

#[test]
fn header_panels_open_close_and_run_their_actions() {
    i_slint_backend_testing::init_integration_test_with_system_time();

    slint::spawn_local(async move {
        let app = AppWindow::new().unwrap();
        let opened_data_folder = Rc::new(Cell::new(0));
        app.on_open_app_data_directory({
            let opened_data_folder = opened_data_folder.clone();
            move || opened_data_folder.set(opened_data_folder.get() + 1)
        });
        app.show().unwrap();

        click(&app, "AppWindow::workspace-picker-area").await;
        assert_eq!(app.get_header_panel().as_str(), "workspace");
        click(&app, "AppWindow::workspace-open-data-action").await;
        assert_eq!(app.get_header_panel().as_str(), "");
        assert_eq!(opened_data_folder.get(), 1);

        app.set_active_page("overview".into());
        click(&app, "AppWindow::local-area").await;
        assert_eq!(app.get_header_panel().as_str(), "local");
        click(&app, "AppWindow::local-go-check-action").await;
        assert_eq!(app.get_active_page().as_str(), "check");
        assert_eq!(app.get_header_panel().as_str(), "");

        app.set_active_page("overview".into());
        click(&app, "AppWindow::notifications-area").await;
        assert_eq!(app.get_header_panel().as_str(), "notifications");
        click(&app, "AppWindow::notifications-open-history-action").await;
        assert_eq!(app.get_active_page().as_str(), "history");
        assert_eq!(app.get_header_panel().as_str(), "");

        click(&app, "AppWindow::about-area").await;
        assert_eq!(app.get_header_panel().as_str(), "about");
        click(&app, "AppWindow::about-open-data-action").await;
        assert_eq!(opened_data_folder.get(), 2);
        assert_eq!(app.get_header_panel().as_str(), "");

        app.set_active_page("overview".into());
        click(&app, "AppWindow::profile-area").await;
        assert_eq!(app.get_header_panel().as_str(), "profile");
        click(&app, "AppWindow::profile-open-profiles-action").await;
        assert_eq!(app.get_active_page().as_str(), "profiles");
        assert_eq!(app.get_header_panel().as_str(), "");

        click(&app, "AppWindow::workspace-picker-area").await;
        click(&app, "AppWindow::header-panel-close-area").await;
        assert_eq!(app.get_header_panel().as_str(), "");

        click(&app, "AppWindow::local-area").await;
        click(&app, "AppWindow::header-panel-backdrop").await;
        assert_eq!(app.get_header_panel().as_str(), "");

        click(&app, "AppWindow::profile-area").await;
        click(&app, "AppWindow::profile-area").await;
        assert_eq!(app.get_header_panel().as_str(), "");

        slint::quit_event_loop().unwrap();
    })
    .unwrap();

    slint::run_event_loop().unwrap();
}
