mod crypto;

use serde::Serialize;

#[derive(Serialize)]
struct DecryptResult {
    plaintext: String,
    method: String,
}

#[tauri::command]
fn decrypt(key: String, ciphertext: String) -> Result<DecryptResult, String> {
    crypto::decrypt(&key, &ciphertext).map(|(plaintext, method)| DecryptResult { plaintext, method })
}

#[tauri::command]
fn encrypt(key: String, plaintext: String, format: String) -> Result<String, String> {
    crypto::encrypt(&key, &plaintext, &format)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![decrypt, encrypt])
        .run(tauri::generate_context!())
        .expect("error al iniciar la aplicación");
}
