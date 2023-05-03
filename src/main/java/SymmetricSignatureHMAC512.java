import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;


public class SymmetricSignatureHMAC512 {

    private static String clientSecret = "4dd863e5-53a8-4c15-bfe3-11902d48fa43";

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, JsonProcessingException {
//        <HTTP METHOD> + ”:” + <RELATIVE PATH URL> + “:“ + LowerCase(HexEncode(SHA-256(Minify(<HTTP BODY>)))) + “:“ + <X-TIMESTAMP>
        String httpMethod = "POST";
        String endpointUrl = "/some-service/snap/v1.0/balance-inquiry";
        String accessToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";

        String requestBody = "{\n" +
                "  \"balanceTypes\": [\n" +
                "    \"BALANCE\"\n" +
                "  ]\n" +
                "}";

        String timestamp = "2023-05-03T11:35:33+07:00";

        String minifyBody = minifyBody(requestBody);
        System.out.println("Minify request body: " + minifyBody);
        String hexEncodedMinifyBody = sha256Hex(minifyBody);
        System.out.println("HexEncode request body: " + hexEncodedMinifyBody);

        String stringToSign = String.join(":", httpMethod, endpointUrl, accessToken, hexEncodedMinifyBody, timestamp);
        System.out.println("String to sign: " + stringToSign);

        String signature = generateSignature(clientSecret, stringToSign);
        System.out.println("Signature: " + signature);
    }

    private static String minifyBody(String input) throws JsonProcessingException {
        ObjectMapper mapper = new ObjectMapper();
        Object jsonObject = mapper.readValue(input, Object.class);
        return mapper.writeValueAsString(jsonObject);
    }

    private static String sha256Hex(String input) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }

    private static String generateSignature(String secret, String input) throws NoSuchAlgorithmException, InvalidKeyException {
        SecretKeySpec secretKey = new SecretKeySpec(secret.getBytes(), "HmacSHA512");
        Mac hmac = Mac.getInstance("HmacSHA512");
        hmac.init(secretKey);
        return Base64.getEncoder().encodeToString(hmac.doFinal(input.getBytes(StandardCharsets.UTF_8)));
    }
}
