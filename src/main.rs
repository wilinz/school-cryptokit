mod myencrypt;

fn main() {
    let key = "000102030405060708090a0b0c0d0e0f"; // 16 字节密钥（32 字符十六进制）
    let password = "my_secret_password";

    // 加密
    let encrypted = myencrypt::encrypt_aes_128_cbc_64prefix(password, key);
    println!("Encrypted: {}", encrypted);

    // 解密
    let decrypted = myencrypt::decrypt_aes_128_cbc_64prefix(&encrypted, key);
    println!("Decrypted: {}", decrypted);

    // 验证解密结果
    assert_eq!(password, decrypted);
}