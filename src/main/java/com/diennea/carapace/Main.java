package com.diennea.carapace;

import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.logging.LogLevel;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import java.io.IOException;
import java.math.BigInteger;
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
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import reactor.core.publisher.Mono;
import reactor.core.publisher.SignalType;
import reactor.netty.ByteBufMono;
import reactor.netty.DisposableServer;
import reactor.netty.http.HttpProtocol;
import reactor.netty.http.client.HttpClient;
import reactor.netty.http.client.HttpClientResponse;
import reactor.netty.http.server.HttpServer;
import reactor.netty.http.server.HttpServerRequest;
import reactor.netty.http.server.HttpServerResponse;
import reactor.netty.transport.logging.AdvancedByteBufFormat;
import reactor.tools.agent.ReactorDebugAgent;

public class Main {

    public static final String PROVIDER = BouncyCastleProvider.PROVIDER_NAME;
    private static final String HOST = "localhost";
    private static final int PORT = 8080;

    static {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        ReactorDebugAgent.init();
    }

    public static void main(final String... args)
            throws NoSuchAlgorithmException, NoSuchProviderException, CertificateException, OperatorCreationException,
            KeyStoreException, IOException, UnrecoverableKeyException {
        final KeyPair rootKeyPair = generateKeyPair();
        final X509Certificate rootCa = buildRootCertificationAuthority(rootKeyPair);

        final KeyPair keyPair = generateKeyPair();
        final X509Certificate httpsCertificate = buildHttpsCertificate(keyPair, rootCa, rootKeyPair.getPrivate());

        final DisposableServer server = setupHttpServer(httpsCertificate, keyPair.getPrivate());

        final HttpClient client = setupHttpClient(rootCa);

        client.get()
                .responseSingle((final HttpClientResponse response, final ByteBufMono byteBufMono) -> {
                    final HttpResponseStatus status = response.status();
                    if (status.code() < 200 || status.code() >= 300) {
                        return Mono.error(new RuntimeException("Server response: " + status));
                    }
                    return byteBufMono.asString();
                })
                .doOnError((final Throwable error) -> {
                    throw new RuntimeException(error);
                })
                .doFinally((final SignalType signalType) -> server.disposeNow())
                .block();
    }

    private static DisposableServer setupHttpServer(final X509Certificate httpsCertificate, final PrivateKey privateKey)
            throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException,
            NoSuchProviderException, UnrecoverableKeyException {
        final KeyStore keyStore = loadKeyStore();
        keyStore.setKeyEntry("httpsCert", privateKey, null, new X509Certificate[] {httpsCertificate});

        final KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
        keyManagerFactory.init(keyStore, null);

        final SslContext sslContext = SslContextBuilder.forServer(keyManagerFactory)
                .sslProvider(io.netty.handler.ssl.SslProvider.OPENSSL)
                .build();

        final HttpServer httpServer = HttpServer
                .create()
                .host(HOST)
                .port(PORT)
                .protocol(HttpProtocol.H2)
                .secure(sslContextSpec -> sslContextSpec.sslContext(sslContext))
                .wiretap(HttpServer.class.getName(), LogLevel.INFO, AdvancedByteBufFormat.HEX_DUMP)
                .metrics(true, Function.identity())
                .handle((final HttpServerRequest request, final HttpServerResponse response) ->
                        response.sendString(Mono.just("Hello from server")));
        return httpServer.bindNow();
    }

    private static HttpClient setupHttpClient(X509Certificate rootCa)
            throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException,
            NoSuchProviderException {
        final KeyStore trustStore = loadKeyStore();
        trustStore.setCertificateEntry("rootCA", rootCa);

        final TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("SunX509");
        trustManagerFactory.init(trustStore);

        final SslContext sslContext = SslContextBuilder.forClient()
                .trustManager(trustManagerFactory)
                .sslProvider(io.netty.handler.ssl.SslProvider.OPENSSL)
                .build();

        return HttpClient
                .create()
                .host(HOST)
                .port(PORT)
                .protocol(HttpProtocol.H2)
                .secure(sslContextSpec -> sslContextSpec.sslContext(sslContext))
                .wiretap(HttpClient.class.getName(), LogLevel.INFO, AdvancedByteBufFormat.HEX_DUMP)
                .metrics(true, Function.identity());
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
        final ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());
        final X509CertificateHolder x509CertificateHolder = x509CertificateBuilder.build(contentSigner);
        return new JcaX509CertificateConverter().setProvider(PROVIDER).getCertificate(x509CertificateHolder);
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
        final ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA").build(rootPrivateKey);
        final X509CertificateHolder x509CertificateHolder = x509CertificateBuilder.build(contentSigner);
        return new JcaX509CertificateConverter().setProvider(PROVIDER).getCertificate(x509CertificateHolder);
    }

    private static KeyStore loadKeyStore()
            throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException,
            NoSuchProviderException {
        final KeyStore keyStore = KeyStore.getInstance("PKCS12", PROVIDER);
        keyStore.load(null, null);
        return keyStore;
    }

    private static KeyPair generateKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", PROVIDER);
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }
}