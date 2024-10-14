package com.diennea.carapace;

import io.netty.handler.codec.http.HttpStatusClass;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.handler.ssl.ApplicationProtocolConfig;
import io.netty.handler.ssl.ApplicationProtocolNames;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslProvider;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.function.Function;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import reactor.core.publisher.Mono;
import reactor.netty.DisposableServer;
import reactor.netty.http.HttpProtocol;
import reactor.netty.http.server.HttpServer;
import reactor.netty.http.server.HttpServerRequest;
import reactor.netty.http.server.HttpServerResponse;
import reactor.tools.agent.ReactorDebugAgent;

import java.net.http.HttpClient;
import javax.net.ssl.SSLContext;

public class Main {

    private static final String JCA_PROVIDER = BouncyCastleProvider.PROVIDER_NAME;
    private static final String JSSE_PROVIDER = BouncyCastleJsseProvider.PROVIDER_NAME;
    private static final String HOST = "localhost";
    private static final int PORT = 8443;
    private static final String KEYSTORE_TYPE = "PKCS12";
    private static final String KEY_ALGORITHM = "RSA";
    private static final String KEY_MANAGER_ALGORITHM = "PKIX";
    private static final String HASH_ALGORITHM = "SHA256";
    private static final String CERT_ALGORITHM = HASH_ALGORITHM + "with" + KEY_ALGORITHM;
    private static final String SSL_CONTEXT_ALGORITHM = "TLS";

    static {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        Security.insertProviderAt(new BouncyCastleJsseProvider(), 2);
        ReactorDebugAgent.init();
    }

    public static void main(final String... args)
            throws NoSuchAlgorithmException, NoSuchProviderException, CertificateException, OperatorCreationException, UnrecoverableKeyException, KeyStoreException, IOException, InterruptedException, KeyManagementException {
        final KeyPair rootKeyPair = generateKeyPair();
        final X509Certificate rootCa = buildRootCertificationAuthority(rootKeyPair);

        final KeyPair keyPair = generateKeyPair();
        final X509Certificate httpsCertificate = buildHttpsCertificate(keyPair, rootCa, rootKeyPair.getPrivate());

        final DisposableServer server = setupHttpServer(httpsCertificate, keyPair.getPrivate());

        try (final HttpClient client = setupHttpClient(rootCa)) {
            final HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create("https://" + HOST + ":" + PORT))
                    .version(HttpClient.Version.HTTP_2)
                    .GET()
                    .version(HttpClient.Version.HTTP_2)
                    .build();

            final HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.version() != HttpClient.Version.HTTP_2) {
                throw new RuntimeException("Server response protocol: " + response.version());
            }

            if (!HttpStatusClass.SUCCESS.contains(response.statusCode())) {
                throw new RuntimeException("Server response: " + response.statusCode());
            }

            System.out.println("Server response: " + response.body());

            server.disposeNow();
        }
    }

    private static KeyPair generateKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM, JCA_PROVIDER);
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    private static X509Certificate buildRootCertificationAuthority(final KeyPair keyPair)
            throws OperatorCreationException, CertificateException {
        final X500Name issuer = new X500NameBuilder()
                .addRDN(BCStyle.CN, new DERUTF8String("Root CA"))
                .addRDN(BCStyle.O, new DERUTF8String("Diennea"))
                .addRDN(BCStyle.OU, new DERUTF8String("Carapace"))
                .addRDN(BCStyle.C, new DERUTF8String("IT"))
                .addRDN(BCStyle.L, new DERUTF8String("Faenza"))
                .addRDN(BCStyle.ST, new DERUTF8String("Ravenna"))
                .addRDN(BCStyle.E, new DERUTF8String("carapace@example.com"))
                .build();
        final long now = System.currentTimeMillis();
        final JcaX509v3CertificateBuilder x509CertificateBuilder = new JcaX509v3CertificateBuilder(
                issuer,
                BigInteger.valueOf(now),
                new Date(now),
                new Date(now + 365 * 24 * 60 * 60 * 1000L /* 1 year */),
                issuer /* self-signed, so issuer and subject are the same */,
                keyPair.getPublic()
        );
        final ContentSigner contentSigner = new JcaContentSignerBuilder(CERT_ALGORITHM).build(keyPair.getPrivate());
        final X509CertificateHolder x509CertificateHolder = x509CertificateBuilder.build(contentSigner);
        return new JcaX509CertificateConverter().setProvider(JCA_PROVIDER).getCertificate(x509CertificateHolder);
    }

    private static X509Certificate buildHttpsCertificate(final KeyPair keyPair, final X509Certificate rootCa,
                                                         PrivateKey rootPrivateKey)
            throws OperatorCreationException, CertificateException {
        final long now = System.currentTimeMillis();
        final JcaX509v3CertificateBuilder x509CertificateBuilder = new JcaX509v3CertificateBuilder(
                rootCa,
                BigInteger.valueOf(now),
                new Date(now),
                new Date(now + 365 * 24 * 60 * 60 * 1000L /* 1 year */),
                new X500NameBuilder().addRDN(BCStyle.CN, HOST).build(),
                keyPair.getPublic()
        );
        final ContentSigner contentSigner = new JcaContentSignerBuilder(CERT_ALGORITHM).build(rootPrivateKey);
        final X509CertificateHolder x509CertificateHolder = x509CertificateBuilder.build(contentSigner);
        return new JcaX509CertificateConverter().setProvider(JCA_PROVIDER).getCertificate(x509CertificateHolder);
    }

    private static DisposableServer setupHttpServer(final X509Certificate httpsCertificate, final PrivateKey privateKey)
            throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException,
            NoSuchProviderException, UnrecoverableKeyException {
        final KeyStore keyStore = loadKeyStore();
        keyStore.setKeyEntry("httpsCert", privateKey, null, new X509Certificate[]{httpsCertificate});

        final KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KEY_MANAGER_ALGORITHM, JSSE_PROVIDER);
        keyManagerFactory.init(keyStore, null);

        final SslContext sslContext = SslContextBuilder
                .forServer(keyManagerFactory)
                .sslProvider(SslProvider.OPENSSL)
                .applicationProtocolConfig(new ApplicationProtocolConfig(
                        // Use ALPN for negotiation
                        ApplicationProtocolConfig.Protocol.ALPN,
                        // Do not advertise if no match
                        ApplicationProtocolConfig.SelectorFailureBehavior.NO_ADVERTISE,
                        // Accept if no protocol is selected
                        ApplicationProtocolConfig.SelectedListenerFailureBehavior.ACCEPT,
                        // Advertise only HTTP/2, do not fall back to HTTP/1.1
                        ApplicationProtocolNames.HTTP_2
                ))
                .build();

        final HttpServer httpServer = HttpServer
                .create()
                .host(HOST)
                .port(PORT)
                .protocol(HttpProtocol.H2)
                .secure(sslContextSpec -> sslContextSpec.sslContext(sslContext))
                // .wiretap(HttpServer.class.getName(), LogLevel.INFO, AdvancedByteBufFormat.HEX_DUMP)
                .metrics(true, Function.identity())
                .handle((final HttpServerRequest request, final HttpServerResponse response) -> {
                    if (HttpVersion.valueOf(request.protocol()).majorVersion() != 2) {
                        throw new RuntimeException("Unsupported HTTP version: " + request.protocol());
                    }
                    return response.sendString(Mono.just("Hello from server"));
                });
        return httpServer.bindNow();
    }

    private static HttpClient setupHttpClient(X509Certificate rootCa)
            throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException, NoSuchProviderException, KeyManagementException {
        final KeyStore trustStore = loadKeyStore();
        trustStore.setCertificateEntry("rootCA", rootCa);

        final TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(KEY_MANAGER_ALGORITHM, JSSE_PROVIDER);
        trustManagerFactory.init(trustStore);

        final SSLContext sslContext = SSLContext.getInstance(SSL_CONTEXT_ALGORITHM, JSSE_PROVIDER);
        sslContext.init(null, trustManagerFactory.getTrustManagers(), null);

        return HttpClient.newBuilder()
                .sslContext(sslContext)
                .version(HttpClient.Version.HTTP_2)
                .build();
    }

    private static KeyStore loadKeyStore()
            throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException,
            NoSuchProviderException {
        final KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE, JCA_PROVIDER);
        keyStore.load(null, null);
        return keyStore;
    }
}
