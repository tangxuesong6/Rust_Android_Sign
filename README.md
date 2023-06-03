## 前言
在 Android 开发中，APK 的签名是一个非常重要的概念。签名用于验证 APK 的完整性和来源，以确保 APK 没有被篡改或恶意修改。在本文中，我们将介绍如何使用 `Rust` 和 `cms` crate(`https://github.com/RustCrypto/formats/tree/master/cms`) 来获取 APK 的签名.

首先，我们需要了解一些基本概念。在 Android 中，APK 的签名是通过使用 Java Cryptography Architecture (JCA) 和 Java Cryptography Extension (JCE) 来实现的。JCA 和 JCE 提供了一组 API，用于生成和验证数字签名。在 Android 中，数字签名通常使用 X.509 证书进行签名和验证.

## 上代码

#### 依赖项
```
[dependencies]
zip = "0.6.4"
anyhow = "1.0.68"
md-5 = "0.10.5"
cms = "0.2.1"
```
* `zip`库用来解压apk.
* `anyhow`库方便我们进行错误处理.
* `md-5`库的主要作用是计算签名文件的`md5`.
* `cms`库则是实现了我们的核心功能,读取签名文件.
#### 读取apk签名
下面是一个 Rust 函数，用于获取 APK 的签名：
```
use std::fs;
use std::io::Read;

use anyhow::{anyhow, Result};
use cms::cert::x509::der::{Decode, Encode};
use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use md5::{Digest, Md5};
use md5::digest::FixedOutput;

pub fn get_sign(apk_path: String) -> Result<String> {
    // Open the APK file as a zip file.
    let zip_file = fs::File::open(apk_path)?;
    let mut zip = zip::ZipArchive::new(zip_file)?;

    // Iterate through all the files in the zip file.
    for i in 0..zip.len() {
        let mut file = zip.by_index(i)?;
        if file.is_file() {
            // Check if the file is a signature file in the META-INF directory.
            if file.name().contains("META-INF") && file.name().contains(".RSA") {
                let mut file_bytes: Vec<u8> = vec![];
                file.read_to_end(&mut file_bytes)?;

                // Parse the signature file as a CMS SignedData structure.
                let content = ContentInfo::from_der(&file_bytes)
                    .map_err(|_| anyhow!("content from der err"))?;
                let der = content.content.to_der()
                    .map_err(|_| anyhow!("der err"))?;
                let data = SignedData::from_der(&der)
                    .map_err(|_| anyhow!("signedData err"))?;

                // Get the first certificate in the SignedData structure.
                let cert = data.certificates.as_ref()
                    .ok_or_else(|| anyhow!("certificates err"))?;
                let choice = cert.0.get(0)
                    .ok_or_else(|| anyhow!("cert.0.get err"))?;

                // Encode the certificate as DER and calculate the MD5 hash of the encoded certificate.
                let der = choice.to_der()
                    .map_err(|_| anyhow!("choice err"))?;
                let mut hasher = Md5::new();
                hasher.update(der);
                let result = hasher.finalize_fixed();

                // Convert the MD5 hash to a hex string and return it as the signature of the APK.
                let hex_sign = result.iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<String>();
                return Ok(hex_sign);
            }
        }
    }
    Err(anyhow!("file read fail"))
}
```

该函数接受一个 APK 文件的路径作为输入，并返回 APK 的签名。该函数使用 fs 和 zip crates 打开 APK 文件并遍历其中的所有文件。如果找到一个名为 .RSA 的文件，则将其解析为 CMS SignedData 结构，并提取其中的第一个证书。然后，将证书编码为 DER 格式，并计算其 MD5 哈希值。最后，将哈希值转换为十六进制字符串，并将其作为 APK 的签名返回.

为了测试该函数，我们可以编写一个简单的测试用例：
```
#[test]
fn test_get_sign() {
    let apk_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../files/app-release.apk");
    println!("apk_path: {:?}", apk_path);
    match get_sign(apk_path.to_str().unwrap().to_string()) {
        Ok(sign) => {
            println!("APK signature: {}", sign);
            assert_eq!(sign, "5a234a41de83f834c3cf4bedd864070a".to_string())
        }
        Err(e) => {
            println!("Error: {}", e);
            panic!("test_get_sign failed")
        }
    };
}
```
该测试用例使用 PathBuf 和 env! 宏来获取 APK 文件的路径，并调用 get_sign 函数来获取 APK 的签名。然后，它使用 assert_eq! 宏来比较实际的签名和预期的签名是否相等.

目前我们的代码还未使用`jni`相关功能,配合`工作空间`模式,我们可以很方便的先在本机上进行调试.
运行测试函数` cargo test -p sign_cms_lib -- --show-output `:
```
---- tests::test_get_sign stdout ----
apk_path: "/home/txs/Center/project/rustProject/rust_android_sign/sign_cms_lib/../files/app-release.apk"
APK signature: 5a234a41de83f834c3cf4bedd864070a


successes:
    tests::test_get_sign
```

可以看到测试通过.

#### 与Android 交互
依赖`jni`实现一个 Rust 模块，它提供了一种方便的方式来获取 Android 设备上 APK 文件的路径。同时使用 `android_logger_lite crate`，可以在 `Android `环境中打印日志。本章使用的`jni`库版本`jni = "0.21.1"`,是目前(2023-06-03)的最新版本.

这个模块包含了以下函数：

get_sign_normal：调用java api获取当前应用的签名，返回签名的 MD5 值.
get_pkg_name：获取当前应用的包名.
get_code_path：获取当前应用的 APK(`getPackageCodePath`) 文件路径.
get_split_path：获取当前应用的Split APK(`String[] split = getPackageManager().getApplicationInfo(getPackageName(),0).splitSourceDirs;`) 文件路径,用来适配google play 商店的`aab`格式.
这些函数都接受一个 JNIEnv 类型的参数，用于调用 Android API。其中，get_sign_normal 函数使用了 java.security.MessageDigest 类来计算签名的 MD5 值。get_split_path 函数使用了 android.content.pm.PackageManager 类来获取应用信息，包括split APK 文件的路径数组.

这个模块还包含了一个 `Java_com_example_rustcmssign_CMSManager_getSign` 函数，它是一个标准的 JNI 函数格式，用于与java进行交互。这个函数首先调用 get_sign_normal 函数获取签名的 MD5 值，然后使用 get_split_path 函数获取 APK 文件路径。如果split APK 文件不存在，则使用 get_code_path 函数获取 APK 文件路径。最后，它使用 sign_cms_lib 模块的函数来获取apk文件的签名，并返回签名的字符串.

这个模块还使用了 android_logger_lite crate 来记录日志.
代码如下:
```

use android_logger_lite as log;
use anyhow::{anyhow, Result};
use jni::JNIEnv;
use jni::objects::{JByteArray, JClass, JObject, JObjectArray, JString, JValue};

// cargo build --target aarch64-linux-android --release  -p sign_jni_lib -Z build-std=std,panic_abort -Z build-std-features=panic_immediate_abort
#[no_mangle]
pub extern "system" fn Java_com_example_rustcmssign_CMSManager_getSign<'local>(mut env: JNIEnv<'local>, _: JClass) -> JString<'local> {
    let sign_normal = get_sign_normal(&mut env).unwrap();
    log::d("SIGN_NORMAL".to_string(), sign_normal.clone());
    let package_code_path: String;
    if let Ok(s) = get_split_path(&mut env) {
        package_code_path = s;
    } else {
        package_code_path = get_code_path(&mut env).unwrap();
    };
    let sig_cms = sign_cms_lib::get_sign(package_code_path).unwrap();
    log::d("SIGN_CMS".to_string(), sig_cms.clone());
    let out = env.new_string(sig_cms).unwrap();
    // if sign2 != REAL_SIGN MD5  then-> report and std::process::abort();
    out
}


pub fn get_sign_normal(env: &mut JNIEnv) -> Result<String> {
    let activity_thread_clz = env.find_class("android/app/ActivityThread")?;
    let application_value = env.call_static_method(activity_thread_clz, "currentApplication", "()Landroid/app/Application;", &[])?;
    let application = JObject::try_from(application_value)?;

    //packageName
    let package_name_value = env.call_method(&application, "getPackageName", "()Ljava/lang/String;", &[])?;

    //PackageManager.GET_SIGNATURES
    let pm_signatures = JValue::from(64);
    let package_manager = env.call_method(application, "getPackageManager", "()Landroid/content/pm/PackageManager;", &[])?;
    let package_info = env.call_method(package_manager.borrow().l()?, "getPackageInfo", "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;", &[(&package_name_value).into(), pm_signatures])?;
    let signatures_value = env.get_field(package_info.l()?, "signatures", "[Landroid/content/pm/Signature;")?;

    //JValue to JObject
    let signature_array_obj = signatures_value.l()?;

    let signature_obj = env.get_object_array_element(JObjectArray::from(signature_array_obj), 0)?;
    let sign_value = env.call_method(signature_obj, "toByteArray", "()[B", &[])?;

    let message_digest_clz = env.find_class("java/security/MessageDigest")?;
    let md5 = env.new_string("md5")?;

    //JString to JValue
    let md5 = JValue::from(&md5);
    let message_digest_value = env.call_static_method(message_digest_clz, "getInstance",
                                                      "(Ljava/lang/String;)Ljava/security/MessageDigest;", &[md5])?;
    let _reset = env.call_method(message_digest_value.borrow().l()?, "reset", "()V", &[])?;
    let _update = env.call_method(message_digest_value.borrow().l()?, "update", "([B)V", &[(&sign_value).into()])?;
    let digest_value = env.call_method(message_digest_value.l()?, "digest", "()[B", &[])?;

    //jarray to Vec
    let digest_array = env.convert_byte_array(JByteArray::from(digest_value.l()?))?;
    //get hex
    let hex_sign: String = digest_array.iter()
        .map(|b| format!("{:02x}", b).to_string())
        .collect::<Vec<String>>().join("");
    Ok(hex_sign)
}

pub fn get_pkg_name(env: &mut JNIEnv) -> Result<String> {
    let activity_thread_clz = env.find_class("android/app/ActivityThread")?;
    let application_value = env.call_static_method(activity_thread_clz, "currentApplication", "()Landroid/app/Application;", &[])?;
    let application = JObject::try_from(application_value)?;

    //packageName
    let package_name_value = env.call_method(&application, "getPackageName", "()Ljava/lang/String;", &[])?;
    //JValue to JString
    let pkg_name = JString::from(package_name_value.l()?);
    //JString to rust String
    let pkg_name: String = env.get_string(&pkg_name)?.into();
    Ok(pkg_name)
}

pub fn get_code_path(env: &mut JNIEnv) -> Result<String> {
    let activity_thread_clz = env.find_class("android/app/ActivityThread")?;

    let application_value = env.call_static_method(activity_thread_clz, "currentApplication", "()Landroid/app/Application;", &[])?;

    let application = application_value.l()?;

    let package_code_path = env.call_method(application, "getPackageCodePath", "()Ljava/lang/String;", &[])?;

    let package_code_path = package_code_path.l()?;

    let package_code_path = JString::from(package_code_path);

    let package_code_path = env.get_string(&package_code_path)?;

    let package_code_path: String = package_code_path.into();
    Ok(package_code_path)
}

//适配 google play split apk
//String[] split = getPackageManager().getApplicationInfo(getPackageName(),0).splitSourceDirs;
pub fn get_split_path(env: &mut JNIEnv) -> Result<String> {
    let activity_thread_clz = env.find_class("android/app/ActivityThread")?;
    let application_value = env.call_static_method(activity_thread_clz, "currentApplication", "()Landroid/app/Application;", &[])?;
    let application = JObject::try_from(application_value)?;

    //packageName
    let package_name_value = env.call_method(&application, "getPackageName", "()Ljava/lang/String;", &[])?;

    let package_manager = env.call_method(application, "getPackageManager", "()Landroid/content/pm/PackageManager;", &[])?;

    let application_info = env.call_method(&package_manager.l()?, "getApplicationInfo", "(Ljava/lang/String;I)Landroid/content/pm/ApplicationInfo;", &[(&package_name_value).into(), 0.into()])?;

    let split_source = env.get_field(&application_info.l()?, "splitSourceDirs", "[Ljava/lang/String;")?;
    let my_arr = JObjectArray::from(split_source.l()?);

    if my_arr.is_null() {
        return Err(anyhow!("{}","array is null"));
    }

    let len = env.get_array_length((&my_arr).into())?;

    let mut arr: Vec<String> = vec![];
    if len > 0 {
        for i in 0..len {
            let str = env.get_object_array_element(&my_arr, i)?;
            let jstr = JString::from(str);
            let value: String = env.get_string(&jstr)?.into();
            if !value.ends_with("base.apk") {
                arr.push(value);
            }
        }
    }

    if arr.len() > 0 {
        return Ok(arr[0].clone());
    } else {
        return Err(anyhow!("{}","no split apk"));
    }
}

```

#### 打包so库
*  for android aarch64
```
export CC=yoursdk/ndk/22.1.7171670/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android30-clang
```
```
export AR=yoursdk/ndk/22.1.7171670/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android-ar
```
```
export RANLIB=yoursdk/ndk/22.1.7171670/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android-ranlib
 ```
* build
```
cargo build --target aarch64-linux-android --release  -p sign_jni_lib -Z build-std=std,panic_abort -Z build-std-features=panic_immediate_abort
```

* 当前rust版本
```
info: The currently active `rustc` version is `rustc 1.72.0-nightly (dd5d7c729 2023-06-02)`
```

最终在`target/aarch64-linux-android/release`	目录下生成一个`so`

```
txs:release/ (master*) $ ls -alh                                                                                                                                                     [22:34:48]
总计 560K
drwxrwxr-x  7 txs txs 4.0K  6月  3 22:33 .
drwxrwxr-x  3 txs txs 4.0K  6月  3 22:32 ..
drwxrwxr-x 17 txs txs 4.0K  6月  3 22:32 build
-rw-rw-r--  1 txs txs    0  6月  3 22:32 .cargo-lock
drwxrwxr-x  2 txs txs  16K  6月  3 22:33 deps
drwxrwxr-x  2 txs txs 4.0K  6月  3 22:32 examples
drwxrwxr-x 87 txs txs 4.0K  6月  3 22:32 .fingerprint
drwxrwxr-x  2 txs txs 4.0K  6月  3 22:32 incremental
-rw-rw-r--  1 txs txs  261  6月  3 22:33 libcms.d
-rwxrwxr-x  2 txs txs 516K  6月  3 22:33 libcms.so

```
可以看到,`so`库大小为`516K`.

#### Android端调用
1. 声明native方法
```
package com.example.rustcmssign;

public class CMSManager {
    static {
        System.loadLibrary("cms");
    }
    public static native String getSign();

}
```

2. 调用
```
        new Thread(new Runnable() {
            @Override
            public void run() {
                String sign = CMSManager.getSign();
                Log.d("MainActivity", "sign: " + sign);
            }
        }).start();
```

结果返回正常.

## 扩展知识
#### Cargo 工作空间(workspaces)
from `GitHub Copilot Chat`插件:
>Rust 的 Workspace 模式是一种组织 Rust 项目的方式，它允许您在一个仓库中管理多个 Rust 项目。Workspace 模式的主要优点是可以方便地共享代码和依赖项，以及在多个项目之间共享构建配置。
在 Workspace 中，您可以将多个 Rust 项目组织在一个父目录下，并使用一个顶层的 Cargo.toml 文件来管理它们的依赖项和构建配置。每个子项目都有自己的 Cargo.toml 文件，但是它们可以共享父项目的依赖项和构建配置。这使得在多个项目之间共享代码和依赖项变得更加容易。
Workspace 模式还允许您使用 Cargo 命令来管理整个 Workspace，例如构建所有项目、运行测试、发布所有项目等。您可以在 Workspace 中使用 cargo build 命令来构建所有项目，或者使用` cargo build -p <package-name> `命令来构建特定的项目。\
要创建一个 Rust Workspace，您可以创建一个包含 Cargo.toml 文件的新目录，并在该文件中添加 [workspace] 部分。然后，您可以在该目录下创建多个子目录，每个子目录都包含一个 Cargo.toml 文件，以定义一个 Rust 项目。



## 总结
本章使用`cms`代替`openssl`实现Android签名验证,相似的验证模式却将包体缩小到了`516K`,非常值得我们使用.


github项目地址`https://github.com/tangxuesong6/Rust_Android_Sign`