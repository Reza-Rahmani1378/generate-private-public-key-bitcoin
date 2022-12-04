import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;

public class GeneratePrivateAndPublicKey {

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {

        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256k1");
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(ecSpec, new SecureRandom());
        KeyPair keypair = g.generateKeyPair();
        PublicKey publicKey = keypair.getPublic();
        PrivateKey privateKey = keypair.getPrivate();

        ECPublicKey epub = (ECPublicKey) publicKey;
        ECPrivateKey ecPrivateKey = (ECPrivateKey) privateKey;
        ECPoint pt = epub.getW();
        ECPoint privateEcpoint = ecPrivateKey.getParams().getGenerator();
        byte[] bcPub = new byte[33];
        byte[] bcPrivate = new byte[33];
        bcPrivate[0] = 1;
        bcPub[0] = 2;
        System.arraycopy(pt.getAffineX().toByteArray(), 0, bcPub, 1, 32);
        System.arraycopy(privateEcpoint.getAffineX().toByteArray(), 0, bcPrivate, 1, 32);

        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] s1 = sha.digest(bcPub);
        byte[] s2 = sha.digest(bcPrivate);

        byte[] ripeMD = Ripemd160.getHash(s1);
        byte[] ripeMD1 = Ripemd160.getHash(s2);

//add 0x00
        byte[] ripeMDPadded = new byte[ripeMD.length + 1];
        ripeMDPadded[0] = 0;
        byte[] ripeMDPadded1 = new byte[ripeMD1.length + 1];
        ripeMDPadded1[0] = 0;

        System.arraycopy(ripeMD, 0, ripeMDPadded, 1, 1);
        System.arraycopy(ripeMD1, 0, ripeMDPadded1, 1, 1);

        byte[] shaFinal = sha.digest(sha.digest(ripeMDPadded));
        byte[] shaFinal1 = sha.digest(sha.digest(ripeMDPadded1));

//append ripeMDPadded + shaFinal = sumBytes
        byte[] sumBytes = new byte[25];
        System.arraycopy(ripeMDPadded, 0, sumBytes, 0, 21);
        System.arraycopy(shaFinal, 0, sumBytes, 21, 4);
        byte[] privateKeyGenerated = new byte[25];
        System.arraycopy(ripeMDPadded1 , 0 , privateKeyGenerated , 0 , 21);


//base 58 encode
        System.out.println("Bitcoin Address: " + Base58.encode(sumBytes));
        System.out.println("Private Key :" + Base58.encode(privateKeyGenerated));
    }
}
