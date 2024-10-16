package com.diennea.carapace;

import java.io.ByteArrayInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.util.Date;
import java.util.HexFormat;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.bc.BcX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class GenerateSelfSigned {

    private static final Provider BC_PROVIDER = new BouncyCastleProvider();
    private static final SecureRandom PRNG = new SecureRandom();

    public static void main(final String[] args) throws Exception {
        Security.insertProviderAt(BC_PROVIDER, 1);

        final KeyPair keyPair = getKeyPair("RSA", 4096);

        final X500Name x500subject = getSubject();
        final X509Certificate x509Cert = getSelfSignedCert(keyPair, x500subject, Validity.ofYears(100), "SHA256WithRSA");
        /*
         * Load Certificate into freshly created Keystore...
         */
        final char[] pwChars = "password".toCharArray();
        final KeyStore keyStore = getKeyStore("PKCS12", keyPair, pwChars, "alias", x509Cert);
        /*
         * Write Certificate & Keystore to disk...
         */
        final String fileName = "self.signed.x509_" + HexFormat.of().toHexDigits(System.currentTimeMillis());

        Files.write(Path.of(fileName + ".cer"), x509Cert.getEncoded());

        keyStore.store(new FileOutputStream(fileName + ".p12"), pwChars);
    }

    private static KeyPair getKeyPair(final String algorithm, final int keysize) throws NoSuchAlgorithmException {
        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm, BC_PROVIDER);
        keyPairGenerator.initialize(keysize, PRNG);

        return keyPairGenerator.generateKeyPair();
    }

    private static X500Name getSubject() {
        return new X500NameBuilder()
                .addRDN(new AttributeTypeAndValue(BCStyle.CN, new DERUTF8String("Common Name")))
                .addRDN(new AttributeTypeAndValue(BCStyle.OU, new DERUTF8String("Organisational Unit name")))
                .addRDN(new AttributeTypeAndValue(BCStyle.O, new DERUTF8String("Organisation")))
                .addRDN(new AttributeTypeAndValue(BCStyle.L, new DERUTF8String("Locality name")))
                .addRDN(new AttributeTypeAndValue(BCStyle.ST, new DERUTF8String("State or Province name")))
                .addRDN(new AttributeTypeAndValue(BCStyle.C, new DERUTF8String("uk")))
                .build();
    }

    private static X509Certificate getSelfSignedCert(final KeyPair keyPair, final X500Name subject, final Validity validity, final String signatureAlgorithm) throws Exception {

        final BigInteger sn = new BigInteger(Long.SIZE, PRNG);

        final X500Name issuer = subject;

        final PublicKey keyPublic = keyPair.getPublic();
        final byte[] keyPublicEncoded = keyPublic.getEncoded();
        final SubjectPublicKeyInfo keyPublicInfo = SubjectPublicKeyInfo.getInstance(keyPublicEncoded);
        /*
         * First, some fiendish trickery to generate the Subject (Public-) Key Identifier...
         */
        try (final ByteArrayInputStream ist = new ByteArrayInputStream(keyPublicEncoded);
             final ASN1InputStream ais = new ASN1InputStream(ist)) {
            final ASN1Sequence asn1Sequence = (ASN1Sequence) ais.readObject();

            final SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(asn1Sequence);
            final SubjectKeyIdentifier subjectPublicKeyId = new BcX509ExtensionUtils().createSubjectKeyIdentifier(subjectPublicKeyInfo);

            /*
             * Now build the Certificate, add some Extensions & sign it with our own Private Key...
             */
            final X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(issuer, sn, validity.notBefore, validity.notAfter, subject, keyPublicInfo);
            final ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).build(keyPair.getPrivate());
            /*
             * BasicConstraints instantiated with "CA=true"
             * The BasicConstraints Extension is usually marked "critical=true"
             *
             * The Subject Key Identifier extension identifies the public key certified by this certificate.
             * This extension provides a way of distinguishing public keys if more than one is available for
             * a given subject name.
             */
            final X509CertificateHolder certHolder = certBuilder
                    .addExtension(Extension.basicConstraints, true, new BasicConstraints(true))
                    .addExtension(Extension.subjectKeyIdentifier, false, subjectPublicKeyId)
                    .build(contentSigner);

            return new JcaX509CertificateConverter().setProvider(BC_PROVIDER).getCertificate(certHolder);
        }
    }

    private static KeyStore getKeyStore(final String keyStoreType, final KeyPair keyPair, final char[] pwChars, final String alias, final X509Certificate x509Cert) throws Exception {

        final KeyStore keyStore = KeyStore.getInstance(keyStoreType);
        keyStore.load(null, pwChars);
        keyStore.setKeyEntry(alias, keyPair.getPrivate(), pwChars, new X509Certificate[]{x509Cert});

        return keyStore;
    }

    private record Validity(Date notBefore, Date notAfter) {

        private static Validity ofYears(final int count) {

            final ZonedDateTime zdtNotBefore = ZonedDateTime.now();
            final ZonedDateTime zdtNotAfter = zdtNotBefore.plusYears(count);

            return of(zdtNotBefore.toInstant(), zdtNotAfter.toInstant());
        }

        private static Validity of(final Instant notBefore, final Instant notAfter) {
            return new Validity(Date.from(notBefore), Date.from(notAfter));
        }
    }
}
