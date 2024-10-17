///usr/bin/env jbang "$0" "$@" ; exit $?
//DEPS io.projectreactor:reactor-tools:3.6.10
//DEPS io.projectreactor.netty:reactor-netty-core:1.1.22
//DEPS io.projectreactor.netty:reactor-netty-http:1.1.22
//DEPS io.netty:netty-tcnative-boringssl-static:2.0.66.Final
//DEPS io.netty:netty-resolver-dns-native-macos:4.1.112.Final
//DEPS org.bouncycastle:bcpkix-jdk18on:1.78.1
//DEPS org.bouncycastle:bcprov-jdk18on:1.78.1
//DEPS org.bouncycastle:bctls-jdk18on:1.78.1
//DEPS org.slf4j:slf4j-api:1.7.33
//DEPS org.slf4j:slf4j-jdk14:1.7.33
//DEPS io.micrometer:micrometer-registry-prometheus:1.13.5

package com.diennea.carapace;

import io.netty.handler.codec.http2.Http2SecurityUtil;
import io.netty.handler.logging.LogLevel;
import io.netty.handler.ssl.ApplicationProtocolConfig;
import io.netty.handler.ssl.ApplicationProtocolNames;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslProvider;
import io.netty.handler.ssl.SupportedCipherSuiteFilter;
import java.io.ByteArrayInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.Date;
import java.util.function.Function;
import javax.net.ssl.TrustManagerFactory;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
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
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import reactor.core.publisher.Mono;
import reactor.netty.ByteBufFlux;
import reactor.netty.DisposableServer;
import reactor.netty.http.HttpProtocol;
import reactor.netty.http.client.HttpClient;
import reactor.netty.http.client.HttpClientResponse;
import reactor.netty.http.server.HttpServer;
import reactor.netty.http.server.HttpServerRequest;
import reactor.netty.http.server.HttpServerResponse;

public class HelloReactorNetty {

    private static final String LOCALHOST = "localhost";
    private static final int PORT = 8443;

    private static final Provider BC_PROVIDER = new BouncyCastleProvider();
    private static final Provider BC_JSSE_PROVIDER = new BouncyCastleJsseProvider();
    private static final SecureRandom PRNG = new SecureRandom();

    private static final String TRUST_MANAGER_ALGORITHM = "PKIX";
    private static final String KEYSTORE_TYPE = "PKCS12";
    private static final String KEY_ALGORITHM = "RSA";
    private static final int KEY_SIZE = 4096;
    private static final String SIGNATURE_ALGORITHM = "SHA256With" + KEY_ALGORITHM;

    public static void main(final String... args) throws Exception {
        Security.insertProviderAt(BC_PROVIDER, 1);
        Security.insertProviderAt(BC_JSSE_PROVIDER, 2);

        final KeyPair keyPair = getKeyPair();
        final var contentSigner = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM)
                .setProvider(BC_PROVIDER)
                .build(keyPair.getPrivate());
        final X509Certificate caCertificate = generateCaCertificate(contentSigner, keyPair.getPublic());

        final X509Certificate httpsCertificate = generateHttpsCertificate(caCertificate, contentSigner);
        final SslContext serverSslContext = SslContextBuilder
                .forServer(keyPair.getPrivate(), httpsCertificate)
                .sslProvider(SslProvider.OPENSSL)
                .ciphers(Http2SecurityUtil.CIPHERS, SupportedCipherSuiteFilter.INSTANCE)
                .applicationProtocolConfig(new ApplicationProtocolConfig(
                        ApplicationProtocolConfig.Protocol.ALPN,
                        ApplicationProtocolConfig.SelectorFailureBehavior.NO_ADVERTISE,
                        ApplicationProtocolConfig.SelectedListenerFailureBehavior.ACCEPT,
                        ApplicationProtocolNames.HTTP_2
                ))
                .build();

        final HttpServer httpServer = HttpServer
                .create()
                .host(LOCALHOST)
                .port(PORT)
                .secure(sslContextSpec -> sslContextSpec.sslContext(serverSslContext))
                .protocol(HttpProtocol.H2)
                .metrics(true, Function.identity())
                .wiretap(HttpServer.class.getName(), LogLevel.INFO)
                .route(routes -> routes
                        .get("/", (final HttpServerRequest request, final HttpServerResponse response) -> {
                            // It always fails here!!!
                            /* if (HttpVersion.valueOf(request.protocol()).majorVersion() != 2) {
                                throw new RuntimeException("Unsupported HTTP version: " + request.protocol());
                            } */
                            System.out.println("Server detected HTTP protocol " + request.protocol());
                            System.out.println("Server detected HTTP version " + request.version());
                            return response.sendString(Mono.just("Hello World!"));
                        })
                        .post("/", (final HttpServerRequest request, final HttpServerResponse response) -> {
                            // It always fails here!!!
                            /* if (HttpVersion.valueOf(request.protocol()).majorVersion() != 2) {
                                throw new RuntimeException("Unsupported HTTP version: " + request.protocol());
                            } */
                            System.out.println("Server detected HTTP protocol " + request.protocol());
                            System.out.println("Server detected HTTP version " + request.version());
                            return response.send(request.receive().retain());
                        })
                );
        final DisposableServer disposableServer = httpServer.bindNow();

        final TrustManagerFactory trustManagerFactory = getTrustManagerFactory(keyPair, caCertificate);
        final SslContext clientSslContext = SslContextBuilder
                .forClient()
                .sslProvider(SslProvider.OPENSSL)
                .ciphers(Http2SecurityUtil.CIPHERS, SupportedCipherSuiteFilter.INSTANCE)
                .applicationProtocolConfig(new ApplicationProtocolConfig(
                        ApplicationProtocolConfig.Protocol.ALPN,
                        ApplicationProtocolConfig.SelectorFailureBehavior.NO_ADVERTISE,
                        ApplicationProtocolConfig.SelectedListenerFailureBehavior.ACCEPT,
                        ApplicationProtocolNames.HTTP_2
                ))
                .trustManager(trustManagerFactory)
                .build();

        final HttpClient httpClient = HttpClient.create()
                .host(disposableServer.host())
                .port(disposableServer.port())
                .secure(sslContextSpec -> sslContextSpec.sslContext(clientSslContext))
                .metrics(true, Function.identity())
                .protocol(HttpProtocol.H2);

        final HttpClientResponse response = httpClient.post()
                .send(ByteBufFlux.fromString(Mono.just("hello")))
                .response()
                .blockOptional()
                .orElseThrow();

        System.out.println("Response status: " + response.status());
        System.out.println("Response HTTP version: " + response.version());

        disposableServer.onDispose().block();
    }

    private static KeyPair getKeyPair() throws NoSuchAlgorithmException {
        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM, BC_PROVIDER);
        keyPairGenerator.initialize(KEY_SIZE, PRNG);
        return keyPairGenerator.generateKeyPair();
    }

    private static X509Certificate generateCaCertificate(final ContentSigner contentSigner, final PublicKey publicKey) throws IOException, CertificateException {
        final byte[] keyPublicEncoded = publicKey.getEncoded();

        // Generate the Subject (Public-) Key Identifier
        // See: <https://stackoverflow.com/a/77292916/7907339>
        final SubjectKeyIdentifier subjectKeyIdentifier;
        try (
                final ByteArrayInputStream ist = new ByteArrayInputStream(keyPublicEncoded);
                final ASN1InputStream ais = new ASN1InputStream(ist)
        ) {
            final ASN1Sequence asn1Sequence = (ASN1Sequence) ais.readObject();
            final SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(asn1Sequence);
            subjectKeyIdentifier = new BcX509ExtensionUtils().createSubjectKeyIdentifier(subjectPublicKeyInfo);
        }

        final X500Name subject = new X500NameBuilder()
                .addRDN(new AttributeTypeAndValue(BCStyle.CN, new DERUTF8String("Common Name")))
                .addRDN(new AttributeTypeAndValue(BCStyle.OU, new DERUTF8String("Organisational Unit name")))
                .addRDN(new AttributeTypeAndValue(BCStyle.O, new DERUTF8String("Organisation")))
                .addRDN(new AttributeTypeAndValue(BCStyle.L, new DERUTF8String("Locality name")))
                .addRDN(new AttributeTypeAndValue(BCStyle.ST, new DERUTF8String("State or Province name")))
                .addRDN(new AttributeTypeAndValue(BCStyle.C, new DERUTF8String("it")))
                .build();

        final ZonedDateTime now = ZonedDateTime.now();
        final X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
                subject,
                generateSerialNumber(),
                Date.from(now.toInstant()),
                Date.from(now.plusYears(1).toInstant()),
                subject,
                SubjectPublicKeyInfo.getInstance(keyPublicEncoded)
        );
        final X509CertificateHolder certHolder = certBuilder
                .addExtension(Extension.basicConstraints, true, new BasicConstraints(true))
                .addExtension(Extension.subjectKeyIdentifier, false, subjectKeyIdentifier)
                .build(contentSigner);
        final X509Certificate certificate = new JcaX509CertificateConverter()
                .setProvider(BC_PROVIDER)
                .getCertificate(certHolder);
        writePemFile("ca.crt", certificate);
        return certificate;
    }

    private static BigInteger generateSerialNumber() {
        return new BigInteger(Long.SIZE, PRNG);
    }

    private static X509Certificate generateHttpsCertificate(final X509Certificate issuer, final ContentSigner contentSigner) throws IOException, CertificateException {
        final JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer,
                generateSerialNumber(),
                issuer.getNotBefore(),
                issuer.getNotAfter(),
                new X500NameBuilder().addRDN(BCStyle.CN, new DERUTF8String(LOCALHOST)).build(),
                issuer.getPublicKey()
        );
        final X509CertificateHolder certHolder = certBuilder
                /*
                 * The Subject Alternative Names (SAN) seems to be required.
                 */
                .addExtension(Extension.subjectAlternativeName, false, new GeneralNames(new GeneralName[]{
                        new GeneralName(GeneralName.dNSName, LOCALHOST),
                        new GeneralName(GeneralName.iPAddress, "127.0.0.1")
                }))
                .build(contentSigner);
        final X509Certificate certificate = new JcaX509CertificateConverter()
                .setProvider(BC_PROVIDER)
                .getCertificate(certHolder);
        writePemFile("certificate.crt", certificate);
        return certificate;
    }

    private static void writePemFile(final String filename, final X509Certificate certificate) throws IOException {
        try (final JcaPEMWriter pemWriter = new JcaPEMWriter(new FileWriter(filename))) {
            pemWriter.writeObject(certificate);
        }
    }

    private static TrustManagerFactory getTrustManagerFactory(final KeyPair keyPair, final X509Certificate x509Cert) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
        final KeyStore keyStore = getKeyStore(keyPair, x509Cert);
        final TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TRUST_MANAGER_ALGORITHM, BC_JSSE_PROVIDER);
        trustManagerFactory.init(keyStore);
        return trustManagerFactory;
    }

    private static KeyStore getKeyStore(final KeyPair keyPair, final X509Certificate x509Cert) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
        final char[] password = "password".toCharArray();
        final KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE, BC_PROVIDER);
        keyStore.load(null, password);
        keyStore.setKeyEntry("alias", keyPair.getPrivate(), password, new X509Certificate[]{x509Cert});
        return keyStore;
    }
}
