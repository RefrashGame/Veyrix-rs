fn main() {
    // Свой манифест: запуск от администратора (WinDivert) + Common Controls v6, как в манифесте Tauri по умолчанию.
    // Только ASCII: компилятор ресурсов портит кириллицу, и Windows отказывается запускать exe (ошибка 14001).
    let windows = tauri_build::WindowsAttributes::new().app_manifest(include_str!("veyrix.manifest"));
    tauri_build::try_build(tauri_build::Attributes::new().windows_attributes(windows)).expect("tauri-build");
}
