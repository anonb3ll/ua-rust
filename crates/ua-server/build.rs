//! Embeds `static/` (htmx, its SSE extension and the stylesheet) for the web
//! UI. Debug builds read the files at request time; release builds embed them.

fn main() {
    memory_serve::load_directory("./static");
}
