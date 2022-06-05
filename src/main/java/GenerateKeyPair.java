import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.BouncyGPG;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPException;

public class GenerateKeyPair {

  public static void main(String[] args)
      throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException, NoSuchProviderException,
      SignatureException {
    BouncyGPG.registerProvider();
    KeyringConfig keyringConfig = BouncyGPG.createSimpleKeyring()
        .simpleEccKeyRing("User <abc@123.com>");

    ByteArrayOutputStream publicOut = new ByteArrayOutputStream();
    try(ArmoredOutputStream out = new ArmoredOutputStream(publicOut)){
      keyringConfig.getPublicKeyRings().encode(out);
    }
    System.out.println(publicOut);

    ByteArrayOutputStream privateOut = new ByteArrayOutputStream();
    try (ArmoredOutputStream out = new ArmoredOutputStream(privateOut)) {
      keyringConfig.getSecretKeyRings().encode(out);
    }
    System.out.println(privateOut);
  }

}
