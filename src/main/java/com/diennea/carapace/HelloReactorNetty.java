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
import io.netty.handler.ssl.ApplicationProtocolConfig;
import io.netty.handler.ssl.ApplicationProtocolNames;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslProvider;
import io.netty.handler.ssl.SupportedCipherSuiteFilter;
import java.io.ByteArrayInputStream;
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
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
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
        final X500Name x500subject = getSubject();
        final X509Certificate x509Cert = getSelfSignedCert(keyPair, x500subject);
        final TrustManagerFactory trustManagerFactory = getTrustManagerFactory(keyPair, x509Cert);

        final SslContext serverSslContext = SslContextBuilder
                .forServer(keyPair.getPrivate(), x509Cert)
                .sslProvider(SslProvider.OPENSSL)
                /* .ciphers(Http2SecurityUtil.CIPHERS, SupportedCipherSuiteFilter.INSTANCE)
                .applicationProtocolConfig(new ApplicationProtocolConfig(
                        ApplicationProtocolConfig.Protocol.ALPN,
                        ApplicationProtocolConfig.SelectorFailureBehavior.NO_ADVERTISE,
                        ApplicationProtocolConfig.SelectedListenerFailureBehavior.ACCEPT,
                        ApplicationProtocolNames.HTTP_2
                )) */
                .build();

        final HttpServer httpServer = HttpServer
                .create()
                .host(LOCALHOST)
                .port(PORT)
                .secure(sslContextSpec -> sslContextSpec.sslContext(serverSslContext))
                .protocol(HttpProtocol.H2)
                .metrics(true, Function.identity())
                .handle((final HttpServerRequest request, final HttpServerResponse response) -> {
                    // It always fails here!!!
                    /* if (HttpVersion.valueOf(request.protocol()).majorVersion() != 2) {
                        throw new RuntimeException("Unsupported HTTP version: " + request.protocol());
                    } */
                    return response.sendString(request.receive().aggregate().asString().map(it -> "Hello! " + it));
                });
        final DisposableServer disposableServer = httpServer.bindNow();

        final SslContext clientSslContext = SslContextBuilder
                .forClient()
                .sslProvider(SslProvider.OPENSSL)
                /* .ciphers(Http2SecurityUtil.CIPHERS, SupportedCipherSuiteFilter.INSTANCE)
                .applicationProtocolConfig(new ApplicationProtocolConfig(
                        ApplicationProtocolConfig.Protocol.ALPN,
                        ApplicationProtocolConfig.SelectorFailureBehavior.NO_ADVERTISE,
                        ApplicationProtocolConfig.SelectedListenerFailureBehavior.ACCEPT,
                        ApplicationProtocolNames.HTTP_2
                )) */
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

        System.out.println(response.status());
        System.out.println(response.version());

        disposableServer.onDispose().block();
    }

    private static KeyPair getKeyPair() throws NoSuchAlgorithmException {
        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM, BC_PROVIDER);
        keyPairGenerator.initialize(KEY_SIZE, PRNG);
        return keyPairGenerator.generateKeyPair();
    }

    private static X500Name getSubject() {
        return new X500NameBuilder()
                .addRDN(new AttributeTypeAndValue(BCStyle.CN, new DERUTF8String("Common Name")))
                .addRDN(new AttributeTypeAndValue(BCStyle.OU, new DERUTF8String("Organisational Unit name")))
                .addRDN(new AttributeTypeAndValue(BCStyle.O, new DERUTF8String("Organisation")))
                .addRDN(new AttributeTypeAndValue(BCStyle.L, new DERUTF8String("Locality name")))
                .addRDN(new AttributeTypeAndValue(BCStyle.ST, new DERUTF8String("State or Province name")))
                .addRDN(new AttributeTypeAndValue(BCStyle.C, new DERUTF8String("it")))
                .build();
    }

    private static X509Certificate getSelfSignedCert(final KeyPair keyPair, final X500Name subject) throws IOException, OperatorCreationException, CertificateException {
        final PublicKey keyPublic = keyPair.getPublic();
        final byte[] keyPublicEncoded = keyPublic.getEncoded();

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

        final ZonedDateTime now = ZonedDateTime.now();
        final X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
                subject, // the certificate issuer is also the subject of the signature
                new BigInteger(Long.SIZE, PRNG), // the certificate serial number
                Date.from(now.toInstant()), // the date before which the certificate is not valid
                Date.from(now.plusYears(1).toInstant()), // the date after which the certificate is not valid
                subject,
                SubjectPublicKeyInfo.getInstance(keyPublicEncoded) // the info structure for the public key
        );
        final ContentSigner contentSigner = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM)
                .setProvider(BC_PROVIDER)
                .build(keyPair.getPrivate());
        final X509CertificateHolder certHolder = certBuilder
                /*
                 * BasicConstraints instantiated with "CA=true"
                 * The BasicConstraints Extension is usually marked "critical=true"
                 */
                .addExtension(Extension.basicConstraints, true, new BasicConstraints(true))
                /*
                 * The Subject Key Identifier extension identifies the public key certified by this certificate.
                 * This extension provides a way of distinguishing public keys
                 * if more than one is available for a given subject name.
                 */
                .addExtension(Extension.subjectKeyIdentifier, false, subjectKeyIdentifier)
                /*
                 * The Subject Alternative Names (SAN) seems also to be required.
                 */
                .addExtension(Extension.subjectAlternativeName, false, new GeneralNames(new GeneralName[]{
                        new GeneralName(GeneralName.dNSName, LOCALHOST),
                        new GeneralName(GeneralName.iPAddress, "127.0.0.1")
                }))
                .build(contentSigner);
        return new JcaX509CertificateConverter().setProvider(BC_PROVIDER).getCertificate(certHolder);
    }

    private static KeyStore getKeyStore(final KeyPair keyPair, final X509Certificate x509Cert) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
        final char[] password = "password".toCharArray();
        final KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE, BC_PROVIDER);
        keyStore.load(/* initialize it freshly */ null, password /* for integrity checking */);
        keyStore.setKeyEntry("alias", keyPair.getPrivate(), password, new X509Certificate[]{x509Cert});
        return keyStore;
    }

    private static TrustManagerFactory getTrustManagerFactory(final KeyPair keyPair, final X509Certificate x509Cert) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
        final KeyStore keyStore = getKeyStore(keyPair, x509Cert);
        final TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TRUST_MANAGER_ALGORITHM, BC_JSSE_PROVIDER);
        trustManagerFactory.init(keyStore);
        return trustManagerFactory;
    }
}
