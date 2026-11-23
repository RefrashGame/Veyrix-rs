// Без лишнего окна консоли в release — не удалять.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    veyrix_lib::run()
}
