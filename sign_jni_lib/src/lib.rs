
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


