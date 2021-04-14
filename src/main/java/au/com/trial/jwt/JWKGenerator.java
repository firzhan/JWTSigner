package au.com.trial.jwt;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;


import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.X509CertUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import javax.xml.bind.*;


import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
//import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.UUID;

public class JWKGenerator {

    public  RSAPublicKey readPublicKey() throws Exception {

        String filename = "/Users/firzhannaqash/Desktop/temp/cer/publickey-der.pem";
        String key = Files.readString(Paths.get(filename), Charset.defaultCharset());

        String publicKeyPEM = key
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END PUBLIC KEY-----", "");

        byte[] encoded = java.util.Base64.getDecoder().decode(publicKeyPEM);

        //byte[] encoded = Base64.decodeBase64(publicKeyPEM);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        return (RSAPublicKey) keyFactory.generatePublic(keySpec);
    }

    public RSAPrivateKey readPrivateKey() throws Exception {
        String filename = "/Users/firzhannaqash/Desktop/temp/cer/privatekey-der.pem";
        String key = Files.readString(Paths.get(filename), Charset.defaultCharset());

        String privateKeyPEM = key
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END PRIVATE KEY-----", "");

        byte[] encoded = java.util.Base64.getDecoder().decode(privateKeyPEM);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
    }

    private PrivateKey generatePrivateKey()
            throws Exception {

        String filename = "/Users/firzhannaqash/Desktop/temp/cer/privatekey-der.pem";
        //String filename1 = "/Users/firzhannaqash/Desktop/temp/private_key.pem";

        byte[] keyBytes = Files.readAllBytes(Paths.get(filename));

       /* JWK jwk = JWK.parseFromPEMEncodedObjects(Files.readString(Paths.get(filename1)));
        System.out.println("KeyType:" + jwk.getKeyType());
        System.out.println("IsPrivate:" + jwk.isPrivate());*/
        //jwk.get
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);

        KeyFactory kf = KeyFactory.getInstance("RSA");
        java.security.interfaces.RSAPrivateKey privateKey = (RSAPrivateKey) kf.generatePrivate(spec);

        return kf.generatePrivate(spec);
    }

    private PublicKey generatePublicKey() throws Exception {

        String filename = "/Users/firzhannaqash/Desktop/temp/cer/publickey-der.pem";

        byte[] keyBytes = Files.readAllBytes(Paths.get(filename));
        X509EncodedKeySpec spec =
                new X509EncodedKeySpec(keyBytes);

        KeyFactory kf = KeyFactory.getInstance("RSA");
        //System.out.println("AAAA" +kf.generatePublic(spec).toString());

        return kf.generatePublic(spec);
    }

    public RSAKey getRSAKey() throws Exception {
        //KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        //keyPairGenerator.initialize(2048);
        //KeyPair keyPair = keyPairGenerator.generateKeyPair();
        //RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        //RSAPrivateKey privateKey = (RSAPrivateKey) generatePrivateKey();
        RSAPrivateKey privateKey = readPrivateKey();
        //RSAPublicKey publicKey = (RSAPublicKey) generatePublicKey();
        RSAPublicKey publicKey = readPublicKey();

       /* CertificateFactory certificateFactory = CertificateFactory.getInstance("PKCS12");
        InputStream certificateInputStream = new FileInputStream("/Users/firzhannaqash/Desktop/temp/private_key.der");
        Certificate certificate = certificateFactory.generateCertificate(certificateInputStream);
*/
        //com.nimbusds.jose.util.Base64 b64 = new com.nimbusds.jose.util.Base64(_x509certificate.toString());     //
        // X509Certificate

        //com.nimbusds.jose.util.Base64

        String cert = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwaJmbxQqmDDPxbdnnDzIBZEUgdADAytw1km0XfQPcc+WwWCjnNn8ECLLuy76VRXfX0IcLTYGGR+a5CZ20upF+RS7mY/Z0zs7u1AnNKntm8eDMYQUIr4PzjJUyBORaZ9hoGBWsktcmxwHz5vRE0NXnBZqjhF61xdQvLe0D6r1eE3Sz9FlsI+w/L6RX2O2t2SLk4jNdpfttkEod3z13/XYpVVVt3wqPBNyeWg0P+H5A/pioF00yV+Xu01NJp/1CreLZS8JsZ3DLryzgzsgJx3kYut3iYoz6AGwkOSeHs8sfaOU5PIzHjaKOOFjDenO9CU/0NIA9moH+zuzKSR6Es7grwIDAQAB";

        String filename1 = "/Users/firzhannaqash/Desktop/temp/private_key.der";
        //byte[] keyBytes = Files.readAllBytes(Paths.get(filename1));
        //String content = Files.readString(Paths.get(filename1));
        //JWK jwk = JWK.parseFromPEMEncodedObjects(Files.readString(Paths.get(filename1)));
        //JWK jwk = JWK.parse(X509CertUtils.parse(keyBytes));

       /*com.nimbusds.jose.util.Base64 b64 =
                new com.nimbusds.jose.util.Base64(DatatypeConverter.printBase64Binary (privateKey.ge));
        // X509Certificate
        ArrayList<com.nimbusds.jose.util.Base64> certificados = new ArrayList<com.nimbusds.jose.util.Base64>();
        certificados.add(b64);
*/
        return  new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.PS256)
                //.x509CertChain(Collections.singletonList(new Base64(privateKey.toString())))
                //.x509CertChain(certificados)
                .keyID("keyId")
                .build();
    }



    public JWKSet generateJWKS(RSAKey rsaKey) {
        JWKSet jwkSet = new JWKSet(rsaKey);
        JsonElement jsonElement =
                new JsonParser().parse(jwkSet.toJSONObject(false).toString());

        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        System.out.println(gson.toJson(jsonElement));

        return jwkSet;
    }




    public static void main(String[] args) throws Exception {

        JWKGenerator jwkGenerator = new JWKGenerator();
        RSAKey rsaKey  = jwkGenerator.getRSAKey();
        jwkGenerator.generateJWKS(rsaKey);

        // Create RSA-signer with the private key
        JWSSigner signer = new RSASSASigner(rsaKey);

        // Prepare JWT with claims set
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("cdr-register")
                .issuer("cdr-register")
                .audience("https://api-uat.np.cdr-api.amp.com.au/cds-au/v1")
                .expirationTime(new Date(new Date().getTime() + 30L * 24 * 60 * 60 * 1000))
                .issueTime(new Date(new Date().getTime()))
                .jwtID(UUID.randomUUID().toString())
                .build();

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.PS256).keyID(rsaKey.getKeyID()).type(JOSEObjectType.JWT).build(),
                claimsSet);

        // Compute the RSA signature
        signedJWT.sign(signer);

        // To serialize to compact form, produces something like
// eyJhbGciOiJSUzI1NiJ9.SW4gUlNBIHdlIHRydXN0IQ.IRMQENi4nJyp4er2L
// mZq3ivwoAjqa1uUkSBKFIX7ATndFF5ivnt-m8uApHO4kfIFOrW7w2Ezmlg3Qd
// maXlS9DhN0nUk_hGI3amEjkKd0BWYCB8vfUbUv0XGjQip78AI4z1PrFRNidm7
// -jPDm5Iq0SZnjKjCNS5Q15fokXZc8u0A
        String s = signedJWT.serialize();

        // On the consumer side, parse the JWS and verify its RSA signature
        signedJWT = SignedJWT.parse(s);

        System.out.println("signedJWT:" + s);
    }



}
