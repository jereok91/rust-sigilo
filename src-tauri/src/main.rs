#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // WebKitGTK + NVIDIA en Wayland falla con "Error 71 (Error de protocolo)"
    // al usar el renderizador DMABUF. Se desactiva salvo que el usuario lo defina.
    #[cfg(target_os = "linux")]
    if std::env::var_os("WEBKIT_DISABLE_DMABUF_RENDERER").is_none() {
        std::env::set_var("WEBKIT_DISABLE_DMABUF_RENDERER", "1");
    }

    rust_sigilo_lib::run()
}
