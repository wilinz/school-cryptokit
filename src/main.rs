use schoolcryptokit::api::myencrypt::{decrypt_aes_128_cbc_64prefix, encrypt_aes_128_cbc_64prefix, get_web_vpn_ordinary_url, get_web_vpn_url};

fn main() {
    let vpnkey = b"wrdvpnisthebest!";
    let vpniv = b"wrdvpnisthebest!";

    let urls = vec![
        "https://bkjw.guet.edu.cn",
        "https://cas.guet.edu.cn",
        "https://v.guet.edu.cn",
        "https://bkjwtest.guet.edu.cn",
        "https://bkjwsrv.guet.edu.cn",
        "https://classroom.guet.edu.cn",
        "https://yjapp.guet.edu.cn",
        "https://pcportal.guet.edu.cn",
        "https://www.guet.edu.cn",    // 图书馆
        "http://202.193.70.166:8020", // 数据库导航
    ];
    for url in urls {
        let encrypt_url = get_web_vpn_url(
            url,
            vpnkey,
            vpniv,
            "https://v.guet.edu.cn",
        );
        println!("enc url: {}", &encrypt_url);
        let decrypt_url = get_web_vpn_ordinary_url(&encrypt_url, vpnkey, vpniv);
        println!("dec url: {}", &decrypt_url);
    }

    for i in 0..10 {
        let key = rand::random::<[u8; 16]>();
        let enc = encrypt_aes_128_cbc_64prefix("hello world", &key);
        println!("{}", enc);
        let dec = decrypt_aes_128_cbc_64prefix(&enc, &key);
        println!("{}", &dec);
    }
}
