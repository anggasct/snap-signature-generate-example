import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;


public class AsymmetricSignatureSHA256WIthRSA {

    private static String publicKey = "-----BEGIN PUBLIC KEY-----\n" +
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq7WjJdnz1J2TDUrlV5mP\n" +
            "dslVw6zhMKK4cyFxwfg9mQUJpN5ktKGoyNkhpq9tADsejKvxDBOk2yzqzx0BnU7y\n" +
            "KDOffUbBiQWQqTTvnEDmxdKn3JyvvO/Gn3OqO461e3z0wlWN9D5mCCncE+Zc178a\n" +
            "spXZ0wW+LUpsuhF62QryZ6zg22iPpIxrTMM14nc360UJ+V+AMoo1TVrM6w/p1kCF\n" +
            "5nIrYbZMRT4CMbPDQdkznWH91cd1MAKI0YYzo0szEzQznDCmbiNmWCBwTywSg6Fy\n" +
            "Ad9/EHEYC/uT4ql3Hq8uxJxLTLWt/OM25gPaLIthes2CL7jHAQ3pUii3jzswXs5D\n" +
            "XQIDAQAB\n" +
            "-----END PUBLIC KEY-----";
    private static String privateKey = "-----BEGIN PRIVATE KEY-----\n" +
            "MIIEuwIBADANBgkqhkiG9w0BAQEFAASCBKUwggShAgEAAoIBAQCrtaMl2fPUnZMN\n" +
            "SuVXmY92yVXDrOEworhzIXHB+D2ZBQmk3mS0oajI2SGmr20AOx6Mq/EME6TbLOrP\n" +
            "HQGdTvIoM599RsGJBZCpNO+cQObF0qfcnK+878afc6o7jrV7fPTCVY30PmYIKdwT\n" +
            "5lzXvxqyldnTBb4tSmy6EXrZCvJnrODbaI+kjGtMwzXidzfrRQn5X4AyijVNWszr\n" +
            "D+nWQIXmcithtkxFPgIxs8NB2TOdYf3Vx3UwAojRhjOjSzMTNDOcMKZuI2ZYIHBP\n" +
            "LBKDoXIB338QcRgL+5PiqXcery7EnEtMta384zbmA9osi2F6zYIvuMcBDelSKLeP\n" +
            "OzBezkNdAgMBAAECgf92DGodm7oGck6m1NbXYrs+7ywHWtN2nGgyvst2jzPJ/6yh\n" +
            "rEOP65QegSihb/mALyTRkWQm6VptVHQZ79csTxosiVEcz4g+q5TIv5v70KLXXfwJ\n" +
            "r68iNbZX6S0fxPz/6OhcsnTldgCvnBexlq49pSS1olAew9P7Ty9wvJO4o84Dd7PB\n" +
            "PecA1nj8z186kF0gDSWwAWrMntf2xiqO9DN+igcyne1ruVMshkQp43bZxDpzXLbp\n" +
            "i8uSpfqn6hXHJSPnRFu+9f2cFUz/OLmdVKYMaO6AVE28Tar6qvhSC9usK3tUDtyD\n" +
            "8mL2ejiU4fEKOB5ORsr2fj8C/DUC/DMLscTVn0ECgYEAtShOyLOAbJZa9Ur3zR7F\n" +
            "dmlJ7DVS6ijgGP5vytXg0qT5K2JgQHhSH0B3yvAs+CA98o/viBpTAy98POv2NEFD\n" +
            "UQzl8yKa3IuBo2OZPPMYO0wSOvU4x5vjvz/YqqDIqC+0QcIqIsk/rj7ztT/oRm3P\n" +
            "hGu/e9XvNwlSaSNELoDrwlsCgYEA8qYXXdubTYMWRlqAAoYTizcihEXjcwUJDxO5\n" +
            "MraR2XTl6Kt6x5XeJ8J2sWz5NVrTzchfn9IhoNOl+hKiNJFZO0SlQ+ttCDpn7pzy\n" +
            "c47/D5EPARpWRdhU/tWzcrgKqjh8H/rS9YPWLO4vYiDEVHgN2Q29Wm8lpqcaXOwe\n" +
            "jLvcjqcCgYARV7SDHjwTKSm4Bd9HMcTxmw7KoCg55oPdoK4PGv6U69o2vwo74cjq\n" +
            "2P8e3HNRpbSIfiMOQobj7S3VnzlIs17AaZ2x8wQkTO6yN5y56wPM2XF9V3CCG3ho\n" +
            "HLKfUxkikL6O9QmXnvCLu9cU6PNRmr2dDbudHVPzTt8m1Yt3cDwhtQKBgQCuHba4\n" +
            "t+PaHA140Gn45aLSi+6twcSzfVKByiJjnJRN2U88xQfmfcka+LTZHhw5SAKiMH1F\n" +
            "nrBYymbYalSQqhfAqsJ4WVA0zkxT8bUcbOjjj7CXlwF/PvvGnSwWTrAAc2XGQOLu\n" +
            "H/so5IWFwYOAJWGydeSBJy56RoBpW1mUnR1oEwKBgCJG5VH4RPdwG+tEO4cra9Az\n" +
            "4GloyS7V9nN/qu8yw19CeCyn06glxUQoU4YGyBr1/u8Tusqup58xcHKPBr9yT9Vw\n" +
            "UEg0hF7sbOoYovWORPoBBzMurg5RQd4toIbMQmUzGJ34/GjM07hPWmmKGiytdvyD\n" +
            "Ca1uFoW7PemUI+44TV21\n" +
            "-----END PRIVATE KEY-----";

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, InvalidKeyException {

        String clientId = "9563b87e-fabd-428a-8732-aafcb255eeec";

        String patternDate = "yyyy-MM-dd'T'HH:mm:ssXXX";
        ZoneId zoneId = ZoneId.of("Asia/Jakarta");
        String xTimestamp = DateTimeFormatter.ofPattern(patternDate).format(ZonedDateTime.of(LocalDateTime.now(), zoneId));

        String input = String.join("|", clientId, xTimestamp);
        System.out.println("Input: " + input);

        String signature = sign(input, privateKey);
        System.out.println("Signature: " + signature);
        boolean verify = verify(input, signature, publicKey);
        System.out.println("Verify: " + verify);
    }

    private static String sign(String input, String privateKey) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        String realPK = clearPrivateKey(privateKey);
        byte[] privateKeyBytes = Base64.getDecoder().decode(realPK);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey pk = kf.generatePrivate(spec);
        Signature sign = Signature.getInstance("SHA256withRSA");
        sign.initSign(pk);
        sign.update(input.getBytes(StandardCharsets.UTF_8));
        byte[] s = sign.sign();
        return Base64.getEncoder().encodeToString(s);
    }

    private static boolean verify(String input, String signature, String publicKey) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        String realPK = clearPublicKey(publicKey);
        byte[] publicKeyBytes = Base64.getDecoder().decode(realPK);
        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey pk = keyFactory.generatePublic(publicKeySpec);
        Signature sign = Signature.getInstance("SHA256withRSA");
        sign.initVerify(pk);
        sign.update(input.getBytes(StandardCharsets.UTF_8));
        byte[] s = Base64.getDecoder().decode(signature);
        return sign.verify(s);
    }

    private static String clearPrivateKey(String pKey) {
        return pKey.replace("-----END PRIVATE KEY-----", "")
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("\n", "");
    }

    private static String clearPublicKey(String pKey) {
        return pKey.replace("-----END PUBLIC KEY-----", "")
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("\n", "");
    }

}
