package com.diennea.carapace;

import static io.netty.handler.ssl.SslProvider.JDK;
import static io.netty.handler.ssl.SslProvider.OPENSSL;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.handler.codec.http2.Http2SecurityUtil;
import io.netty.handler.ssl.ApplicationProtocolConfig;
import io.netty.handler.ssl.ApplicationProtocolNames;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslProvider;
import io.netty.handler.ssl.SupportedCipherSuiteFilter;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import java.io.ByteArrayInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
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
import java.util.function.Function;
import javax.net.ssl.TrustManagerFactory;
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
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.bc.BcX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import reactor.core.publisher.Mono;
import reactor.netty.DisposableServer;
import reactor.netty.http.Http2SslContextSpec;
import reactor.netty.http.HttpProtocol;
import reactor.netty.http.client.HttpClient;
import reactor.netty.http.server.HttpServer;
import reactor.netty.http.server.HttpServerRequest;
import reactor.netty.http.server.HttpServerResponse;

public class Http2Demo {

    private static final Provider BC_PROVIDER = new BouncyCastleProvider();
    private static final SecureRandom PRNG = new SecureRandom();
    private static final String LOCALHOST = "localhost";

    public static void main(final String[] args) throws Exception {
        Security.insertProviderAt(BC_PROVIDER, 1);

        final KeyPair keyPair = getKeyPair("RSA", 4096);

        final X500Name x500subject = getSubject();
        final X509Certificate x509Cert = getSelfSignedCert(keyPair, x500subject, Validity.ofYears(100), "SHA256WithRSA");

        final HttpServer httpServer = HttpServer
                .create()
                .host(LOCALHOST)
                .secure(sslContextSpec -> sslContextSpec.sslContext(Http2SslContextSpec.forServer(keyPair.getPrivate(), x509Cert)))
                .protocol(HttpProtocol.H2)
                .metrics(true, Function.identity())
                .handle((final HttpServerRequest request, final HttpServerResponse response) -> {
                    // we can't check request.protocol() here, it will always be HTTP/1.1 !!!
                    if (HttpVersion.valueOf(request.protocol()).majorVersion() != 2) {
                        throw new RuntimeException("Unsupported HTTP version: " + request.protocol());
                    }
                    return response.sendString(Mono.just("Hello from server"));
                });
        final DisposableServer disposableServer = httpServer.bindNow();

        /*
         * Load Certificate into freshly created Keystore...
         */
        final char[] pwChars = "password".toCharArray();
        final KeyStore keyStore = getKeyStore("PKCS12", keyPair, pwChars, "alias", x509Cert);
        final TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(keyStore);
        final SslContext sslContext = SslContextBuilder
                .forClient()
                .sslProvider(SslProvider.isAlpnSupported(OPENSSL) ? OPENSSL : JDK)
                .ciphers(Http2SecurityUtil.CIPHERS, SupportedCipherSuiteFilter.INSTANCE)
                .applicationProtocolConfig(new ApplicationProtocolConfig(
                        ApplicationProtocolConfig.Protocol.ALPN,
                        ApplicationProtocolConfig.SelectorFailureBehavior.NO_ADVERTISE,
                        ApplicationProtocolConfig.SelectedListenerFailureBehavior.ACCEPT,
                        ApplicationProtocolNames.HTTP_2,
                        ApplicationProtocolNames.HTTP_1_1))
                .trustManager(trustManagerFactory)
                .build();

        final HttpClient httpClient = HttpClient.create()
                .host(disposableServer.host())
                .port(disposableServer.port())
                .secure(sslContextSpec -> sslContextSpec.sslContext(sslContext))
                .protocol(HttpProtocol.H2);

        httpClient.get().response().block();
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
        try (
                final ByteArrayInputStream ist = new ByteArrayInputStream(keyPublicEncoded);
                final ASN1InputStream ais = new ASN1InputStream(ist)
        ) {
            final ASN1Sequence asn1Sequence = (ASN1Sequence) ais.readObject();
            final SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(asn1Sequence);
            final SubjectKeyIdentifier subjectPublicKeyId = new BcX509ExtensionUtils().createSubjectKeyIdentifier(subjectPublicKeyInfo);

            /*
             * Now build the Certificate, add some Extensions & sign it with our own Private Key...
             */
            final X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(issuer, sn, validity.notBefore, validity.notAfter, subject, keyPublicInfo)
                    /*
                     * BasicConstraints instantiated with "CA=true"
                     * The BasicConstraints Extension is usually marked "critical=true"
                     *
                     * The Subject Key Identifier extension identifies the public key certified by this certificate.
                     * This extension provides a way of distinguishing public keys if more than one is available for
                     * a given subject name.
                     */
                    .addExtension(Extension.basicConstraints, true, new BasicConstraints(true))
                    .addExtension(Extension.subjectKeyIdentifier, false, subjectPublicKeyId)
                    .addExtension(Extension.subjectAlternativeName, false, new GeneralNames(new GeneralName[]{
                            new GeneralName(GeneralName.dNSName, LOCALHOST),
                            new GeneralName(GeneralName.iPAddress, "127.0.0.1")
                    }));
            final ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).build(keyPair.getPrivate());
            final X509CertificateHolder certHolder = certBuilder.build(contentSigner);

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
