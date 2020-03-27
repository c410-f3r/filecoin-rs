class ExtendedKey {
  String privateKey;
  String publicKey;
  String publicKeyCompressed;
  String address;

  public ExtendedKey(String prvkey, String pubkey, String pubkeyc, String a) {
    privateKey = prvkey;
    publicKey = pubkey;
    publicKeyCompressed = pubkeyc;
    address = a;
  }
}


class Signer {
    private static native String generate_mnemonic();
    private static native ExtendedKey key_derive(String mnemonic, String path);

    static {
        // This actually loads the shared object that we'll be creating.
        // The actual location of the .so or .dll may differ based on your
        // platform.
        System.loadLibrary("signer");
    }
}
