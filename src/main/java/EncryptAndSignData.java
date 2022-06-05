import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.BouncyGPG;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeyringConfigCallbacks;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.InMemoryKeyring;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfigs;
import org.bouncycastle.openpgp.PGPException;

public class EncryptAndSignData {

  public static void main(String[] args) throws Exception {
    BouncyGPG.registerProvider();
    String sender = "sender@robothy.com";
    String receiver = "receiver@robothy.com";

    KeyringConfig senderKeyring = generateKeyring(sender);
    KeyringConfig receiverKeyring = generateKeyring(receiver);

    /* The sender encrypt and sign data */
    InMemoryKeyring encryptAndSignKeyring = KeyringConfigs.forGpgExportedKeys(KeyringConfigCallbacks.withUnprotectedKeys());
    // Receiver's public key
    encryptAndSignKeyring.addPublicKey(receiverKeyring.getPublicKeyRings().getEncoded());
    // Sender's private key
    encryptAndSignKeyring.addSecretKey(senderKeyring.getSecretKeyRings().getEncoded());
    encryptAndSignKeyring.addPublicKey(senderKeyring.getPublicKeyRings().getEncoded());

    String message = "Hello World.";
    ByteArrayOutputStream encryptedData = new ByteArrayOutputStream();
    try (OutputStream out = BouncyGPG.encryptToStream()
        .withConfig(encryptAndSignKeyring)
        .withStrongAlgorithms()
        .toRecipient(receiver) // Encrypt with recipient's public key
        .andSignWith(sender) // Sign with sender's private key
        .binaryOutput()
        .andWriteTo(encryptedData)) {
      out.write(message.getBytes(StandardCharsets.UTF_8));
    }


    /* The receiver decrypt data and verify the signature */
    InMemoryKeyring decryptKeyring = KeyringConfigs.forGpgExportedKeys(KeyringConfigCallbacks.withUnprotectedKeys());
    // Sender's public key
    decryptKeyring.addPublicKey(senderKeyring.getPublicKeyRings().getEncoded());
    // Receiver's private key
    decryptKeyring.addSecretKey(receiverKeyring.getSecretKeyRings().getEncoded());

    try (InputStream in = BouncyGPG.decryptAndVerifyStream()
        .withConfig(decryptKeyring)
        .andRequireSignatureFromAllKeys(sender) // Verify signature with sender's public key
        .fromEncryptedInputStream(new ByteArrayInputStream(encryptedData.toByteArray()))) { // Decrypt data with receiver's private key
      assert message.equals(new String(in.readAllBytes()));
    }
  }

  static KeyringConfig generateKeyring(String user)
      throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException, NoSuchProviderException {
    return BouncyGPG.createSimpleKeyring()
        .simpleEccKeyRing("User <" + user + ">"); // see ByEMailKeySelectionStrategy
  }

}
