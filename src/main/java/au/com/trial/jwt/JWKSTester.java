package au.com.trial.jwt;

import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Properties;
import java.util.UUID;

public class JWKSTester {

    private static final Logger logger = LoggerFactory.getLogger(JWKSTester.class);


    //openssl genrsa -out key.pem 2048

    //nodes creates without password, means no DES encryption
    ///openssl req -x509 -newkey rsa:2048 -keyout myKey.pem -out cert.pem -days 365 -nodes

    //openssl pkcs12 -export -out keyStore.p12 -inkey myKey.pem -in cert.pem -name "alias"

    private Certificate certificate;
    private String alias;
    private String keyPass;
    private String jwksURL;
    private String subject;
    private String issuer;
    private String audience;
    private KeyPair keyPair;
    private JWSAlgorithm algorithm;

    public JWKSTester(){
        try {
            loadProperties();
            loadKeyPair();
        } catch (Exception e) {
            logger.error("Failed to load the key-pair", e);
        }
    }

    private void loadProperties(){

        Properties prop = new Properties();
        try (InputStream inputStream = JWKSTester.class.getClassLoader().getResourceAsStream("config.properties")) {

            // load a properties file
            prop.load(inputStream);
            this.alias = prop.getProperty("alias") == null ? "" : prop.getProperty("alias");
            this.keyPass = prop.getProperty("keyPass") == null ? "" : prop.getProperty("keyPass");
            this.jwksURL = prop.getProperty("jwksURL");
            this.issuer = prop.getProperty("issuer");
            this.audience = prop.getProperty("audience");
            this.subject = prop.getProperty("subject");
            this.algorithm = JWSAlgorithm.parse(prop.getProperty("algo"));
            // get the property value and print it out
        } catch (IOException ex) {
            logger.error("Failed loading the config file", ex);
        }
    }

    private void loadKeyPair() throws Exception {
        // Read keystore from resource folder
        InputStream inputStream = JWKSTester.class.getClassLoader().getResourceAsStream("keyStore.p12");
        char[] keyPass = this.keyPass.toCharArray();
        //String alias = "alias";
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
       /* try (FileInputStream is = new FileInputStream(file)) {
            keystore.load(is, keyPass);
        }*/
        keystore.load(inputStream, keyPass);

        Key key = keystore.getKey(this.alias, keyPass);
        if (key instanceof PrivateKey) {
            // Get certificate of public key
            Certificate cert = keystore.getCertificate(alias);
            this.certificate = cert;

            this.keyPair = new KeyPair(cert.getPublicKey(), (PrivateKey) key);

            // Get public key
         /*   this.publicKey = cert.getPublicKey();
            this.privateKey = (PrivateKey) key;*/

        }
    }

    /*public KeyPair loadKeyPair() throws Exception {
        // Read keystore from resource folder
        InputStream inputStream = JWKSTester.class.getClassLoader().getResourceAsStream("keyStore.p12");

        char[] keyPass = "".toCharArray();
        String alias = "alias";

        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
       *//* try (FileInputStream is = new FileInputStream(file)) {
            keystore.load(is, keyPass);
        }*//*
        keystore.load(inputStream, keyPass);

        Key key = keystore.getKey(alias, keyPass);
        if (key instanceof PrivateKey) {
            // Get certificate of public key
            Certificate cert = keystore.getCertificate(alias);

            this.certificate = cert;

            // Get public key
            PublicKey publicKey = cert.getPublicKey();

            // Return a key pair
            return new KeyPair(publicKey, (PrivateKey) key);
        }

        return null;
    }*/

    public RSAKey generateRSAKey() throws CertificateEncodingException, NoSuchAlgorithmException {

        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");

        return  new RSAKey.Builder((RSAPublicKey) this.keyPair.getPublic())
                .privateKey(this.keyPair.getPrivate())
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(this.algorithm)
                .x509CertChain(Collections.singletonList(Base64.encode(this.certificate.getEncoded())))
                .x509CertSHA256Thumbprint(Base64URL.encode(sha256.digest(this.certificate.getEncoded())))
                .keyID("keyId")
                .build();
    }

    public void generateJWKS(RSAKey rsaKey) {
        //JWKSet jwkSet = new JWKSet(rsaKey);
        logger.info("JWK Key: {}",
                new JWKSet(rsaKey).toJSONObject(false).toString());
    }

    public String createdSignedJWT(RSAKey rsaKey) throws JOSEException {

        // Create RSA-signer with the private key
        JWSSigner signer = new RSASSASigner(rsaKey);


        // Prepare JWT with claims set
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject(this.subject)
                .issuer(this.issuer)
                .audience(this.audience)
                .expirationTime(new Date(new Date().getTime() + 30L * 24 * 60 * 60 * 1000))
                .issueTime(new Date(new Date().getTime()))
                .jwtID(UUID.randomUUID().toString())
                .build();

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(this.algorithm).keyID(rsaKey.getKeyID()).type(JOSEObjectType.JWT).build(),
                claimsSet);

        // Compute the RSA signature
        signedJWT.sign(signer);

        // To serialize to compact form, produces something like
        // eyJhbGciOiJSUzI1NiJ9.SW4gUlNBIHdlIHRydXN0IQ.IRMQENi4nJyp4er2L
        // mZq3ivwoAjqa1uUkSBKFIX7ATndFF5ivnt-m8uApHO4kfIFOrW7w2Ezmlg3Qd
        // maXlS9DhN0nUk_hGI3amEjkKd0BWYCB8vfUbUv0XGjQip78AI4z1PrFRNidm7
        // -jPDm5Iq0SZnjKjCNS5Q15fokXZc8u0A
        return signedJWT.serialize();

       // On the consumer side, parse the JWS and verify its RSA signature
        //signedJWT = SignedJWT.parse(s);



        //return signedJWT;
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    public void verifyJWT(String jwtToken) throws MalformedURLException, BadJOSEException, ParseException,
            JOSEException {

        // Create a JWT processor for the access tokens
        ConfigurableJWTProcessor<SecurityContext> jwtProcessor =
                new DefaultJWTProcessor<>();

        jwtProcessor.setJWSTypeVerifier(
                new DefaultJOSEObjectTypeVerifier<>(JOSEObjectType.JWT));

        // The public RSA keys to validate the signatures will be sourced from the
        // OAuth 2.0 server's JWK set, published at a well-known URL. The RemoteJWKSet
        // object caches the retrieved keys to speed up subsequent look-ups and can
        // also handle key-rollover
        //ResourceRetriever resourceRetriever = new DefaultResourceRetriever(50000, 50000, 51200);
        JWKSource<SecurityContext> keySource =
                new RemoteJWKSet<>(new URL(this.jwksURL)/*,
                        resourceRetriever*/);
        // The expected JWS algorithm of the access tokens (agreed out-of-band)
        //JWSAlgorithm expectedJWSAlg = JWSAlgorithm.PS256;

        // Configure the JWT processor with a key selector to feed matching public
// RSA keys sourced from the JWK set URL
        JWSKeySelector<SecurityContext> keySelector =
                new JWSVerificationKeySelector<>(this.algorithm, keySource);

        jwtProcessor.setJWSKeySelector(keySelector);


        jwtProcessor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier(
                new JWTClaimsSet.Builder().issuer("cdr-register").build(),
                new HashSet<>(Arrays.asList("sub", "aud", "iss", "iat", "exp", "iat", "jti"))));

        // Process the token
        JWTClaimsSet claimsSet = jwtProcessor.process(jwtToken, null);

        JsonElement claims = JsonParser.parseString(claimsSet.toJSONObject(false).toString());
        logger.info("Verified Claims: {}",
                claims.toString());

    }



    public static void main(String[] args) throws Exception {

        JWKSTester jwksTester = new JWKSTester();
        //KeyPair keyPair = jwksTester.loadKeyPair();
        RSAKey rsaKey = jwksTester.generateRSAKey();
        jwksTester.generateJWKS(rsaKey);
        String jwtString = jwksTester.createdSignedJWT(rsaKey);
        logger.info("JWT Token: {}", jwtString);
        jwksTester.verifyJWT(jwtString);
    }
}
