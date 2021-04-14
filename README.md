# Generating Private and Public Key Pair

##Generate a 2048-bit RSA private key

```openssl genrsa -out key.pem 2048```

###Generate a 2048-bit RSA private key and CSR

```openssl req -x509 -newkey rsa:2048 -keyout myKey.pem -out cert.pem -days 365 -nodes```

- **openssl** – Activates the OpenSSL
- **req** – Indicates that we want a CSR
- **-x509 –newkey** – Generates a new key
- **rsa:2048** – Generates a 2048-bit RSA mathematical key
- **–nodes** – No DES, meaning do not encrypt the private key in a PKCS#12 file
- **–out** – Specifies the name of the file your CSR will be saved as

###Export the private key, publick key and certificate into a p12 file
```openssl pkcs12 -export -out keyStore.p12 -inkey myKey.pem -in cert.pem -name "alias"```

The output p12 file ***keyStore.p12*** should be copied to the src/main/resources folder.

# Update the config properties.

  The config file location could be located inside the ***resources*** folder.


# Executing the Jar
    
  ```mvn clean install```
  
  ```java -jar target/JWTSigner-1.0-jar-with-dependencies.jar```