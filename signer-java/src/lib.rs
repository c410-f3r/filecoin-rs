use filecoin_signer;
use jni::objects::{JClass, JString, JValue};
use jni::sys::{jobject, jstring};
use jni::JNIEnv;
//use jni::Result;

#[repr(C)]
pub struct ExtendedKey(filecoin_signer::ExtendedKey);

impl ExtendedKey {
    pub fn to_slice(&self) -> &[JValue] {
        // Need to create an array of JString with the prvkey, pubkey, compressedpubkey, address
        // and return it
    }
}

#[no_mangle]
pub extern "system" fn Java_Signer_generate_1mnemonic(env: JNIEnv, _class: JClass) -> jstring {
    let mnemonic = filecoin_signer::key_generate_mnemonic().unwrap();

    let output = env
        .new_string(mnemonic.0)
        .expect("Couldn't create java string!");

    output.into_inner()
}

#[no_mangle]
pub extern "system" fn Java_Signer_key_1derive(
    env: JNIEnv,
    _class: JClass,
    mnemonic: JString,
    path: JString,
) -> jobject {
    let mnemonic_rust: String = env
        .get_string(mnemonic)
        .expect("Couldn't get the mnemonic java string!")
        .into();

    let path_rust: String = env
        .get_string(path)
        .expect("Couldn't get the path java string!")
        .into();

    let ext_key =
        filecoin_signer::key_derive(filecoin_signer::Mnemonic(mnemonic_rust), path_rust).unwrap();

    let extended_key = ExtendedKey { 0: ext_key };

    // This call the java constructor of the ExtendedKey java class in Signer.java (normaly)
    let output = env.new_object("ExtendedKey", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)LExtendedKey", &extended_key).unwrap();

    output.into_inner()
}
