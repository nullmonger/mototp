use dioxus::desktop::{Config, WindowBuilder};

mod entry;
mod otp;
mod otpauth;
mod query;
mod store;
mod ui;

fn main() {
    dioxus::LaunchBuilder::desktop()
        .with_cfg(Config::new().with_window(WindowBuilder::new().with_title("mototp")))
        .launch(ui::app);
}
