# octave_data_encryption_standard

DES / 3DES primitives for GNU Octave, including the private bit order used by
QQMusic / LyricTools.exe and the full QRC decryption pipeline.

```octave
pkg install octave_data_encryption_standard.tar.gz -local
pkg load octave_data_encryption_standard

des_selftest ()
[xml, info] = qrc_decrypt_file ('test.qrc');

% 自定义分组密码（函数句柄 / 回调结构体 / 注册名称）
xorfn = @(block, key, dir) bitxor (block, key);
c = des_blockcrypt (block, key, 1, xorfn);
des_register_variant ('xor8', xorfn, xorfn);
c = des_blockcrypt (block, key, 1, 'xor8');
```

`des_core.oct` is built with the standard Linux toolchain:

```sh
cd src
./configure            # finds mkoctfile, sets ZLIB=-lz
make
```

## Documentation

Check out document: [octave_data_encryption_standard Document](https://cnoctave.github.io/octave_data_encryption_standard/index.html)

## How to translate octave_data_encryption_standard Document into another language
In ./docs directory, index.html is zh-CN simplified Chinese document.
For example, if you want to translate document into English.
1. Copy index.html as another document with different language code as filename,
   for example, en-US.html.
2. Translate en-US.html into English.
3. Add dropdown like the picture below to every *.html.
   For example, add dropdown "en-US English".
   ![the dropdown looking](./docs/translate_dropdown.png)
   The code for adding dropdown is like the picture below.
   ![the dropdown code](./docs/translate_dropdown_code.png)
4. PR to octave_data_encryption_standard.
