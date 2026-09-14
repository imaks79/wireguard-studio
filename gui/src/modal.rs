/// A simple modal popup. egui has no blocking `messagebox`-style dialogs
/// like Tk, so info/error/preview windows are modeled as app-level state
/// rendered as an `egui::Window` each frame instead.
#[derive(Clone)]
pub enum Modal {
    Info { title: String, body: String },
    Error { title: String, body: String },
    /// A read-only, copyable preview of generated text (a `.conf` file or
    /// a RouterOS script), with its own Copy button.
    Preview { title: String, body: String },
}
