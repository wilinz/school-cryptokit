# 学校统一认证登录密码加解密（AES/CBC/PCks5）以及 WebVpn 加解密（AES/CFB）的 rust 库

## 密码加解密原理
疑问：为啥 IV 可以随机，因为 IV 是用来偏移第一个加密块的，第二个以及后面的加密块不会收到IV影响即可正常解密，因为偏移的规则是后一个块使用前一个块当中它的"IV"，第一个块才用到传入的 IV, 所以即使 IV 不对只会解不出第一个块而已，后面的块并不会受到影响，所以咱们把前 64 个填充字节去掉就可以了
```rust
// 加密函数
pub fn encrypt_aes_128_cbc_64prefix(plain: &str, key: &[u8]) -> String {
    if key.len() != 16 && key.len() != 24 && key.len() != 32 {
        panic!("Key must be 16, 24, or 32 bytes long");
    }

    // 生成随机的 IV（16 字节）
    let mut iv = [0u8; 16];
    rng().fill(&mut iv);

    // 生成 64 字节的随机字符串
    let random_str: String = rng()
        .sample_iter(&Alphanumeric)
        .take(64)
        .map(char::from)
        .collect();

    // 拼接随机字符串和密码
    let plaintext = format!("{}{}", random_str, plain);

    // 使用 AES-CBC 加密
    let cipher = Cipher::aes_128_cbc(); // 根据密钥长度选择 AES-128/192/256
    let encrypted =
        encrypt(cipher, &key, Some(&iv), plaintext.as_bytes()).expect("Encryption failed");

    base64::engine::general_purpose::STANDARD.encode(&encrypted)
}

// 解密函数
pub fn decrypt_aes_128_cbc_64prefix(encrypted_base64: &str, key: &[u8]) -> String {
    // 将密钥转换为字节数组
    if key.len() != 16 && key.len() != 24 && key.len() != 32 {
        panic!("Key must be 16, 24, or 32 bytes long");
    }

    // 解码 Base64
    let encrypted_data = base64::engine::general_purpose::STANDARD
        .decode(encrypted_base64)
        .expect("Invalid Base64");

    // 生成随机的 IV（16 字节）
    let mut iv = [0u8; 16];
    rng().fill(&mut iv);

    // 使用 AES-CBC 解密
    let cipher = Cipher::aes_128_cbc(); // 根据密钥长度选择 AES-128/192/256
    let decrypted = decrypt(cipher, &key, Some(&iv), &encrypted_data)
        .expect("Decryption failed")
        .split_off(64); // 去掉填充的64字节

    // 将解密结果转换为字符串
    let decrypted_str = String::from_utf8(decrypted).expect("Invalid UTF-8");

    // 提取原始密码（去掉前面的 64 字节随机字符串）
    decrypted_str
}
```

## WebVpn 加解密原理
```rust
pub fn get_encrypt_web_vpn_host(plaintext: &str, key: &[u8], iv: &[u8]) -> String {
    let cipher = Cipher::aes_128_cfb128();
    let encrypted =
        encrypt(cipher, key, Some(iv), plaintext.as_bytes()).expect("Encryption failed");
    hex_encode(encrypted)
}

pub fn get_decrypt_web_vpn_host(ciphertext: &str, key: &[u8], iv: &[u8]) -> String {
    let ct = hex_decode(ciphertext).expect("Invalid hex");
    let cipher = Cipher::aes_128_cfb128();
    let decrypted = decrypt(cipher, key, Some(iv), &ct).expect("Decryption failed");
    String::from_utf8(decrypted).expect("Invalid UTF-8")
}
```

以下是编译成动态库的命令

编译
```shell
cargo build --release
```

生成头文件
```shell
cargo install --force cbindgen
```

```shell
cbindgen --config cbindgen.toml --crate guethubcrypto --output guethubcrypto.h
```
