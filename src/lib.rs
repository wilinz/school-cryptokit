mod ffi; // 导入封装层模块
mod myencrypt; // 假设原始函数在 myencrypt 模块中
// 导出原始函数
pub use myencrypt::{set_vpn_host, get_vpn_url, get_ordinary_url, get_encrypt_host, get_decrypt_host, encrypt_aes_128_cbc_64prefix, decrypt_aes_128_cbc_64prefix};