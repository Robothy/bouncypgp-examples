import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.BouncyGPG;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms.PGPAlgorithmSuite;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms.PGPCompressionAlgorithms;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms.PGPHashAlgorithms;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms.PGPSymmetricEncryptionAlgorithms;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeyringConfigCallbacks;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.type.length.RsaLength;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.InMemoryKeyring;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfigs;
import org.bouncycastle.openpgp.PGPException;

public class EncryptData {

  public static void main(String[] args)
      throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException, NoSuchProviderException,
      SignatureException {

    BouncyGPG.registerProvider();

    // Generate key pair for recipient
    String recipient = "recipient@robothy.com";
    KeyringConfig receiverKeyring = generateKeyring(recipient);

    // Keyring for encrypt data
    InMemoryKeyring encryptKeying = KeyringConfigs.forGpgExportedKeys(KeyringConfigCallbacks.withUnprotectedKeys());
    encryptKeying.addPublicKey(receiverKeyring.getPublicKeyRings().getEncoded());

    // Encrypt with the public key of recipient.
    String message = "Hello World";
    ByteArrayOutputStream encryptedData = new ByteArrayOutputStream();
    try (OutputStream out = BouncyGPG.encryptToStream()
        .withConfig(encryptKeying)
        .withAlgorithms(new PGPAlgorithmSuite(PGPHashAlgorithms.MD5,
            PGPSymmetricEncryptionAlgorithms.AES_128, PGPCompressionAlgorithms.ZIP))
        .toRecipient(recipient)
        .andDoNotSign()
        .binaryOutput()
        .andWriteTo(encryptedData)) {
      out.write(message.getBytes(StandardCharsets.UTF_8));
    }

    /*----- Recipient decrypt data with his private key -----*/

    // Keyring for decrypt data
    InMemoryKeyring decryptKeyring = KeyringConfigs.forGpgExportedKeys(KeyringConfigCallbacks.withUnprotectedKeys());
    decryptKeyring.addSecretKey(receiverKeyring.getSecretKeyRings().getEncoded());
    try (InputStream in = BouncyGPG.decryptAndVerifyStream()
        .withConfig(decryptKeyring)
        .andIgnoreSignatures()
        .fromEncryptedInputStream(new ByteArrayInputStream(encryptedData.toByteArray()))) {
      assert message.equals(new String(in.readAllBytes()));
    }

  }

  static KeyringConfig generateKeyring(String email)
      throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException, NoSuchProviderException {
    return BouncyGPG.createSimpleKeyring()
        .simpleRsaKeyRing("<" + email + ">", RsaLength.RSA_2048_BIT);
  }

}
