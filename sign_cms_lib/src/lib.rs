use std::fs;
use std::io::Read;

use anyhow::{anyhow, Result};
use cms::cert::x509::der::{Decode, Encode};
use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use md5::{Digest, Md5};
use md5::digest::FixedOutput;



// This function takes the path of an APK file as input and returns the signature of the APK as a string.
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

// cargo test -p sign_cms_lib -- --show-output
#[cfg(test)]

mod tests {
    use std::path::PathBuf;
    use crate::get_sign;

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
}