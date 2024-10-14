package com.diennea.carapace;

import io.netty.handler.ssl.ApplicationProtocolConfig;
import io.netty.handler.ssl.ApplicationProtocolNames;
import io.netty.handler.ssl.OpenSsl;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslProvider;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
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
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.function.Function;
import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManagerFactory;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import reactor.core.publisher.Mono;
import reactor.netty.DisposableServer;
import reactor.netty.http.HttpProtocol;
import reactor.netty.http.server.HttpServer;
import reactor.netty.http.server.HttpServerRequest;
import reactor.netty.http.server.HttpServerResponse;
import reactor.tools.agent.ReactorDebugAgent;

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
    private static final int OCSP_PORT = 8080;

    static {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        Security.insertProviderAt(new BouncyCastleJsseProvider(), 2);

        // https://docs.oracle.com/en/java/javase/21/security/java-secure-socket-extension-jsse-reference-guide.html
        Security.setProperty("ocsp.enable", "true"); // Enable client-driven OCSP
        System.setProperty("jdk.tls.client.enableStatusRequestExtension", "true"); // Enable OCSP stapling on the client
        System.setProperty("com.sun.net.ssl.checkRevocation", "true"); // Enable revocation checking; alternative to PKIXParameters#setRevocationEnabled

        // System.setProperty("javax.net.debug", "all");
        ReactorDebugAgent.init();

        if (!OpenSsl.isAvailable()) {
            throw new IllegalStateException("OpenSSL is not available!");
        }

        if (!OpenSsl.isOcspSupported()) {
            throw new IllegalStateException("OCSP is not supported!");
        }
    }

    public static void main(final String... args) throws Exception {
        final KeyPair rootKeyPair = generateKeyPair();
        final X509Certificate rootCa = buildRootCertificationAuthority(rootKeyPair);

        final KeyPair keyPair = generateKeyPair();
        final X509Certificate httpsCertificate = buildHttpsCertificate(keyPair, rootCa, rootKeyPair.getPrivate());

        // Start OCSP Responder
        final DisposableServer ocspResponder = setupOcspResponder(rootCa, rootKeyPair);

        // Send OCSP request and verify the certificate status
        verifyCertificateWithOCSP(rootCa, httpsCertificate);

        ocspResponder.onDispose().block();

        /* final DisposableServer server = setupHttpServer(httpsCertificate, keyPair.getPrivate());

        server.onDispose().block(); */

        /* try (final HttpClient client = setupHttpClient(rootCa)) {
            final HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create("https://" + HOST + ":" + PORT))
                    .GET()
                    .build();

            final HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

//            if (response.version() != HttpClient.Version.HTTP_2) {
//                throw new RuntimeException("Server response protocol: " + response.version());
//            }
//
//            if (!HttpStatusClass.SUCCESS.contains(response.statusCode())) {
//                throw new RuntimeException("Server response: " + response.statusCode());
//            }
//
//            final SSLSession sslSession = response.sslSession().orElseThrow();
//            if (!(sslSession instanceof ExtendedSSLSession extendedSSLSession)) {
//                throw new RuntimeException("SSL Session of unexpected type: " + sslSession);
//            }
//            // The OCSP response is encoded using the Distinguished Encoding Rules (DER) in a format described by the ASN.1 found in RFC 6960
//            final List<byte[]> statusResponses = extendedSSLSession.getStatusResponses();
//            if (statusResponses == null || statusResponses.isEmpty()) {
//                throw new RuntimeException("OCSP response missing.");
//            }

            System.out.println("Server response: " + response.body());

            server.disposeNow();
        } */
    }

    // Generates an OCSP request for the provided certificate
    private static OCSPReq generateOCSPRequest(
            final X509Certificate issuerCert, final X509Certificate clientCert
    ) throws OperatorCreationException, CertificateEncodingException, IOException, OCSPException {
        final var digestCalculator = new JcaDigestCalculatorProviderBuilder().build().get(CertificateID.HASH_SHA1);
        final CertificateID certificateID = new CertificateID(
                digestCalculator, new X509CertificateHolder(issuerCert.getEncoded()), clientCert.getSerialNumber()
        );
        final OCSPReqBuilder ocspReqBuilder = new OCSPReqBuilder();
        ocspReqBuilder.addRequest(certificateID);
        return ocspReqBuilder.build();
    }

    // Send OCSP request and get the response from the OCSP server
    private static OCSPResp sendOCSPRequest(
            final URI ocspUri, final byte[] ocspRequestBytes
    ) throws IOException, InterruptedException {
        try (HttpClient httpClient = HttpClient.newHttpClient()) {
            final HttpRequest request = HttpRequest.newBuilder()
                    .uri(ocspUri)
                    .header("Content-Type", "application/ocsp-request")
                    .POST(HttpRequest.BodyPublishers.ofByteArray(ocspRequestBytes))
                    .build();
            final HttpResponse<byte[]> response = httpClient.send(request, HttpResponse.BodyHandlers.ofByteArray());
            return new OCSPResp(response.body());
        }
    }

    // Parse and check the OCSP response
    private static void parseOCSPResponse(final OCSPResp ocspResp) throws OCSPException {
        if (ocspResp.getStatus() != OCSPRespBuilder.SUCCESSFUL) {
            throw new RuntimeException("OCSP response is not successful: " + ocspResp.getStatus());
        }
        final BasicOCSPResp basicResponse = (BasicOCSPResp) ocspResp.getResponseObject();
        final CertificateStatus certStatus = basicResponse.getResponses()[0].getCertStatus();
        if (certStatus == CertificateStatus.GOOD) {
            System.out.println("The certificate is GOOD.");
            return;
        }
        if (certStatus instanceof org.bouncycastle.cert.ocsp.RevokedStatus) {
            System.out.println("The certificate is REVOKED.");
            return;
        }
        throw new RuntimeException("The certificate status is UNKNOWN.");
    }

    private static void verifyCertificateWithOCSP(X509Certificate caCert, X509Certificate clientCert) throws OCSPException, IOException, InterruptedException, CertificateEncodingException, OperatorCreationException {
        // Generate OCSP request
        OCSPReq ocspRequest = generateOCSPRequest(caCert, clientCert);

        // Send request to the OCSP responder
        URI ocspUri = URI.create("http://localhost:8080/ocsp");
        OCSPResp ocspResp = sendOCSPRequest(ocspUri, ocspRequest.getEncoded());

        // Parse and validate the OCSP response
        parseOCSPResponse(ocspResp);
    }

    private static KeyPair generateKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM, JCA_PROVIDER);
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    private static X509Certificate buildRootCertificationAuthority(final KeyPair keyPair)
            throws OperatorCreationException, CertificateException, CertIOException {
        final X500Name issuer = new X500NameBuilder()
                .addRDN(BCStyle.CN, new DERUTF8String("Root CA"))
                .addRDN(BCStyle.O, new DERUTF8String("Diennea"))
                .addRDN(BCStyle.OU, new DERUTF8String("Carapace"))
                .addRDN(BCStyle.C, new DERUTF8String("IT"))
                .addRDN(BCStyle.L, new DERUTF8String("Faenza"))
                .addRDN(BCStyle.ST, new DERUTF8String("Ravenna"))
                .build();

        final long now = System.currentTimeMillis();
        final BigInteger serialNumber = BigInteger.valueOf(new SecureRandom().nextInt());

        final JcaX509v3CertificateBuilder x509CertificateBuilder = new JcaX509v3CertificateBuilder(
                issuer,
                serialNumber,
                new Date(now),
                new Date(now + 365 * 24 * 60 * 60 * 1000L /* 1 year */),
                issuer /* self-signed, so issuer and subject are the same */,
                keyPair.getPublic()
        );

        final ContentSigner contentSigner = new JcaContentSignerBuilder(CERT_ALGORITHM).build(keyPair.getPrivate());
        final X509CertificateHolder x509CertificateHolder = x509CertificateBuilder
                .addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.cRLSign | KeyUsage.keyCertSign))
                .addExtension(Extension.basicConstraints, true, new BasicConstraints(true)) // This is a CA
                .build(contentSigner);
        return new JcaX509CertificateConverter().setProvider(JCA_PROVIDER).getCertificate(x509CertificateHolder);
    }

    private static X509Certificate buildHttpsCertificate(
            final KeyPair keyPair, final X509Certificate rootCa, final PrivateKey rootPrivateKey
    ) throws OperatorCreationException, CertificateException {
        final long now = System.currentTimeMillis();
        final JcaX509v3CertificateBuilder x509CertificateBuilder = new JcaX509v3CertificateBuilder(
                rootCa,
                BigInteger.valueOf(now),
                new Date(now),
                new Date(now + 365 * 24 * 60 * 60 * 1000L /* 1 year */),
                new X500NameBuilder().addRDN(BCStyle.CN, HOST).build(),
                keyPair.getPublic()
        );
        final ContentSigner contentSigner = new JcaContentSignerBuilder(CERT_ALGORITHM)
                .setProvider(JCA_PROVIDER)
                .build(rootPrivateKey);
        final X509CertificateHolder x509CertificateHolder = x509CertificateBuilder.build(contentSigner);
        return new JcaX509CertificateConverter()
                .setProvider(JCA_PROVIDER)
                .getCertificate(x509CertificateHolder);
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
                        ApplicationProtocolConfig.Protocol.ALPN,
                        ApplicationProtocolConfig.SelectorFailureBehavior.NO_ADVERTISE,
                        ApplicationProtocolConfig.SelectedListenerFailureBehavior.ACCEPT,
                        ApplicationProtocolNames.HTTP_2
                ))
                .enableOcsp(true)
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
                    // we can't check request.protocol() here, it will always be HTTP/1.1 !!!
                    /* if (HttpVersion.valueOf(request.protocol()).majorVersion() != 2) {
                        throw new RuntimeException("Unsupported HTTP version: " + request.protocol());
                    } */
                    return response.sendString(Mono.just("Hello from server"));
                });
        return httpServer.bindNow();
    }

    private static KeyStore loadKeyStore()
            throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, NoSuchProviderException {
        final KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE, JCA_PROVIDER);
        keyStore.load(null, null);
        return keyStore;
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

    private static DisposableServer setupOcspResponder(final X509Certificate caCert, final KeyPair caKeyPair) {
        return HttpServer.create()
                .host(HOST)
                .port(OCSP_PORT)
                .handle((final HttpServerRequest request, final HttpServerResponse response) -> request
                        .receive()
                        .aggregate()
                        .asByteArray()
                        .flatMap(ocspRequestBytes -> {
                            try {
                                final OCSPReq ocspRequest = new OCSPReq(ocspRequestBytes);
                                final CertificateID certificateID = ocspRequest.getRequestList()[0].getCertID();
                                final BasicOCSPRespBuilder responseBuilder = new BasicOCSPRespBuilder(
                                        SubjectPublicKeyInfo.getInstance(caKeyPair.getPublic().getEncoded()),
                                        new JcaDigestCalculatorProviderBuilder()
                                                .setProvider(JCA_PROVIDER)
                                                .build()
                                                .get(CertificateID.HASH_SHA1)
                                );
                                responseBuilder.addResponse(certificateID, CertificateStatus.GOOD);
                                final ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSAEncryption")
                                        .setProvider(JCA_PROVIDER)
                                        .build(caKeyPair.getPrivate());
                                final BasicOCSPResp basicResponse = responseBuilder.build(contentSigner, null, new Date());
                                final OCSPRespBuilder ocspRespBuilder = new OCSPRespBuilder();
                                final byte[] ocspResponseBytes = ocspRespBuilder
                                        .build(OCSPRespBuilder.SUCCESSFUL, basicResponse)
                                        .getEncoded();
                                return response
                                        .header("Content-Type", "application/ocsp-response")
                                        .sendByteArray(Mono.just(ocspResponseBytes))
                                        .then();
                            } catch (IOException | OCSPException | OperatorCreationException e) {
                                return Mono.error(e);
                            }
                        })
                )
                .bindNow();
    }
}
