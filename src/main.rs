use dioxus::desktop::{Config, WindowBuilder};
use dioxus::prelude::*;

mod entry;
mod otp;
mod otpauth;

fn main() {
    dioxus::LaunchBuilder::desktop()
        .with_cfg(Config::new().with_window(WindowBuilder::new().with_title("mototp")))
        .launch(app);
}

fn app() -> Element {
    rsx! {}
}
