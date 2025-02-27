

编译
```shell
cargo build --release
```

生成头文件
```shell
cargo install --force cbindgen
```

```shell
cbindgen --config cbindgen.toml --crate hubcrypto --output hubcrypto.h
```