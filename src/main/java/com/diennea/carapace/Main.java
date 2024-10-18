package com.diennea.carapace;

import io.netty.handler.codec.http.HttpStatusClass;
import io.netty.handler.ssl.ApplicationProtocolConfig;
import io.netty.handler.ssl.ApplicationProtocolNames;
import io.netty.handler.ssl.OpenSsl;
import io.netty.handler.ssl.OpenSslCachingX509KeyManagerFactory;
import io.netty.handler.ssl.ReferenceCountedOpenSslEngine;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslHandler;
import io.netty.handler.ssl.SslProvider;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.Date;
import java.util.List;
import java.util.function.Consumer;
import java.util.function.Function;
import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManagerFactory;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
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
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
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

    private static final Provider BC_PROVIDER = new BouncyCastleProvider();
    private static final Provider BC_JSSE_PROVIDER = new BouncyCastleJsseProvider();
    private static final SecureRandom PRNG = new SecureRandom();

    private static final String HOST = "localhost";
    private static final int PORT = 8443;
    private static final String KEYSTORE_TYPE = "PKCS12";
    private static final String KEY_ALGORITHM = "RSA";
    private static final String KEY_MANAGER_ALGORITHM = "PKIX";
    private static final String HASH_ALGORITHM = "SHA256";
    private static final String CERT_ALGORITHM = HASH_ALGORITHM + "with" + KEY_ALGORITHM;
    private static final String SSL_CONTEXT_ALGORITHM = "TLS";
    private static final int OCSP_PORT = 8080;
    private static final URI OCSP_RESPONDER_URL = URI.create("http://" + HOST + ":" + OCSP_PORT + "/ocsp");

    static {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        Security.insertProviderAt(new BouncyCastleJsseProvider(), 2);

        // https://docs.oracle.com/en/java/javase/21/security/java-secure-socket-extension-jsse-reference-guide.html
        Security.setProperty("ocsp.enable", "true"); // Enable client-driven OCSP
        System.setProperty("jdk.tls.client.enableStatusRequestExtension", "true"); // Enable OCSP stapling on the client
        System.setProperty("jdk.tls.server.enableStatusRequestExtension", "true"); // Enable OCSP stapling on the server
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
        // Generate a root self-signed certificate that acts as a CA...
        final KeyPair rootKeyPair = generateKeyPair();
        final ContentSigner contentSigner = new JcaContentSignerBuilder(CERT_ALGORITHM).build(rootKeyPair.getPrivate());
        final X509Certificate rootCa = buildRootCertificationAuthority(rootKeyPair.getPublic(), contentSigner);

        // Save the root CA certificate to a file
        saveCertificateToFile(rootCa, "rootCA.crt");

        // ... and generate an HTTPS certificate signed by the CA
        final KeyPair keyPair = generateKeyPair();
        final X509Certificate httpsCertificate1 = buildHttpsCertificate(keyPair, rootCa, contentSigner);
        final X509Certificate httpsCertificate2 = buildHttpsCertificate(keyPair, rootCa, contentSigner);

        // Save the HTTPS certificate to a file
        saveCertificateToFile(httpsCertificate1, "httpsCertificate1.crt");
        saveCertificateToFile(httpsCertificate2, "httpsCertificate2.crt");

        // Start OCSP Responder
        final DisposableServer ocspResponder = setupOcspResponder(rootKeyPair);

        // Send OCSP request and verify the certificate status
        verifyCertificateWithOCSP(rootCa, httpsCertificate1);
        verifyCertificateWithOCSP(rootCa, httpsCertificate2);

//        ocspResponder.onDispose().block();

        final DisposableServer server = setupHttpServer(rootCa, keyPair.getPrivate(), httpsCertificate1, httpsCertificate2);

//        server.onDispose().block();

//        Mono.when(ocspResponder.onDispose(), server.onDispose()).block();

        try (final HttpClient client = setupHttpClient(rootCa)) {
            final HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create("https://" + HOST + ":" + PORT))
                    .GET()
                    .build();

            final HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.version() != HttpClient.Version.HTTP_2) {
                throw new RuntimeException("Server response protocol: " + response.version());
            }

            if (!HttpStatusClass.SUCCESS.contains(response.statusCode())) {
                throw new RuntimeException("Server response: " + response.statusCode());
            }

            final SSLSession sslSession = response.sslSession().orElseThrow();
            if (!(sslSession instanceof ExtendedSSLSession extendedSSLSession)) {
                throw new RuntimeException("SSL Session of unexpected type: " + sslSession);
            }

            // The OCSP response is encoded using the Distinguished Encoding Rules (DER) in a format described by the ASN.1 found in RFC 6960
            final List<byte[]> statusResponses = extendedSSLSession.getStatusResponses();
            if (statusResponses == null || statusResponses.isEmpty()) {
                throw new RuntimeException("OCSP response missing.");
            } else {
                System.out.println("Received OCSP responses: " + statusResponses.size());
            }

            System.out.println("Server response: " + response.body());

            server.disposeNow();
        }
    }

    private static KeyPair generateKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM, BC_PROVIDER);
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    private static X509Certificate buildRootCertificationAuthority(final PublicKey publicKey, final ContentSigner contentSigner) throws CertificateException, CertIOException {
        final X500Name issuer = new X500NameBuilder()
                .addRDN(BCStyle.CN, new DERUTF8String("Root CA"))
                .addRDN(BCStyle.O, new DERUTF8String("Diennea"))
                .addRDN(BCStyle.OU, new DERUTF8String("Carapace"))
                .addRDN(BCStyle.C, new DERUTF8String("IT"))
                .addRDN(BCStyle.L, new DERUTF8String("Faenza"))
                .addRDN(BCStyle.ST, new DERUTF8String("Ravenna"))
                .build();

        final ZonedDateTime now = ZonedDateTime.now();
        final JcaX509v3CertificateBuilder x509CertificateBuilder = new JcaX509v3CertificateBuilder(
                issuer,
                new BigInteger(Long.SIZE, PRNG),
                Date.from(now.toInstant()),
                Date.from(now.plusYears(1).toInstant()),
                issuer /* self-signed, so issuer and subject are the same */,
                publicKey
        );

        final X509CertificateHolder x509CertificateHolder = x509CertificateBuilder
                .addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.cRLSign | KeyUsage.keyCertSign))
                .addExtension(Extension.basicConstraints, true, new BasicConstraints(true)) // This is a CA
                .build(contentSigner);
        return new JcaX509CertificateConverter().setProvider(BC_PROVIDER).getCertificate(x509CertificateHolder);
    }

    private static void saveCertificateToFile(X509Certificate certificate, String filename) throws IOException {
        try (final JcaPEMWriter pemWriter = new JcaPEMWriter(new FileWriter(filename))) {
            pemWriter.writeObject(certificate);
        }
        System.out.println("Saved certificate to " + filename);
    }

    private static X509Certificate buildHttpsCertificate(final KeyPair keyPair, final X509Certificate rootCa, final ContentSigner contentSigner) throws CertificateException, IOException {
        final var subject = new X500NameBuilder()
                .addRDN(BCStyle.CN, new DERUTF8String(HOST))
                .addRDN(BCStyle.OU, new DERUTF8String("Italy"))
                .addRDN(BCStyle.O, new DERUTF8String("Italy"))
                .addRDN(BCStyle.L, new DERUTF8String("Italy"))
                .addRDN(BCStyle.ST, new DERUTF8String("Italy"))
                .addRDN(BCStyle.C, new DERUTF8String("XX"))
                .build();
        final JcaX509v3CertificateBuilder x509CertificateBuilder = new JcaX509v3CertificateBuilder(
                rootCa,
                new BigInteger(Long.SIZE, PRNG),
                rootCa.getNotBefore(),
                rootCa.getNotAfter(),
                subject,
                keyPair.getPublic()
        );

        // Add the AIA extension with the OCSP responder URI
        final Extension aiaExtension = new Extension(
                Extension.authorityInfoAccess,
                false, // extension is not critical
                new DERSequence(new AccessDescription(
                        AccessDescription.id_ad_ocsp,
                        new GeneralName(
                                GeneralName.uniformResourceIdentifier,
                                OCSP_RESPONDER_URL.toString() // OCSP responder URI
                        )
                )).getEncoded()
        );

        x509CertificateBuilder.addExtension(aiaExtension);

        final X509CertificateHolder x509CertificateHolder = x509CertificateBuilder.build(contentSigner);
        return new JcaX509CertificateConverter()
                .setProvider(BC_PROVIDER)
                .getCertificate(x509CertificateHolder);
    }

    private static DisposableServer setupOcspResponder(final KeyPair caKeyPair) {
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
                                                .setProvider(BC_PROVIDER)
                                                .build()
                                                .get(CertificateID.HASH_SHA1)
                                );

                                // Here, modify the status as needed (e.g., GOOD, REVOKED, etc.)
                                responseBuilder.addResponse(certificateID, CertificateStatus.GOOD);
                                final ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSAEncryption")
                                        .setProvider(BC_PROVIDER)
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
                                e.printStackTrace(); // Log the error for debugging
                                return Mono.error(e);
                            }
                        })
                )
                .bindNow();
    }

    private static void verifyCertificateWithOCSP(final X509Certificate caCert, final X509Certificate clientCert) throws OCSPException, IOException, InterruptedException, GeneralSecurityException, OperatorCreationException {
        final OCSPReq ocspRequest = generateOCSPRequest(caCert, clientCert);
        final OCSPResp ocspResp = sendOCSPRequest(OCSP_RESPONDER_URL, ocspRequest.getEncoded());
        parseOCSPResponse(ocspResp);
    }

    private static DisposableServer setupHttpServer(final X509Certificate issuer, final PrivateKey privateKey, final X509Certificate httpsCertificate, final X509Certificate httpsCertificateSni) throws GeneralSecurityException, IOException {
        final KeyStore keyStore = loadKeyStore();
        keyStore.setKeyEntry("httpsCert", privateKey, null, new X509Certificate[]{httpsCertificate});
        keyStore.setKeyEntry("altHttpsCert", privateKey, null, new X509Certificate[]{httpsCertificateSni});

        final KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KEY_MANAGER_ALGORITHM, BC_JSSE_PROVIDER);
        keyManagerFactory.init(keyStore, null);

        final SslContext sslContext = SslContextBuilder
                .forServer(keyManagerFactory)
                .sslProvider(SslProvider.OPENSSL)
                .applicationProtocolConfig(new ApplicationProtocolConfig(
                        ApplicationProtocolConfig.Protocol.ALPN,
                        ApplicationProtocolConfig.SelectorFailureBehavior.NO_ADVERTISE,
                        ApplicationProtocolConfig.SelectedListenerFailureBehavior.ACCEPT,
                        ApplicationProtocolNames.HTTP_2,
                        ApplicationProtocolNames.HTTP_1_1
                ))
                .enableOcsp(true)
                .build();

        final KeyManagerFactory keyFactory = new OpenSslCachingX509KeyManagerFactory(KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()));
        keyFactory.init(keyStore, null);

        final SslContext sslContextLocalhost = SslContextBuilder
                .forServer(keyFactory)
                .sslProvider(SslProvider.OPENSSL)
                .applicationProtocolConfig(new ApplicationProtocolConfig(
                        ApplicationProtocolConfig.Protocol.ALPN,
                        ApplicationProtocolConfig.SelectorFailureBehavior.NO_ADVERTISE,
                        ApplicationProtocolConfig.SelectedListenerFailureBehavior.ACCEPT,
                        ApplicationProtocolNames.HTTP_2,
                        ApplicationProtocolNames.HTTP_1_1
                ))
                .enableOcsp(true)
                .build();

        final HttpServer httpServer = HttpServer
                .create()
                .host(HOST)
                .port(PORT)
                .protocol(HttpProtocol.H2, HttpProtocol.HTTP11)
                .secure(sslContextSpec -> sslContextSpec
                        .sslContext(sslContext)
                        .handlerConfigurator(getSslHandlerConsumer(issuer, httpsCertificate))
                        .addSniMapping("localhost", sslContextSpec1 -> sslContextSpec1
                                .sslContext(sslContextLocalhost)
                                .handlerConfigurator(getSslHandlerConsumer(issuer, httpsCertificateSni)))
                )
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

    private static Consumer<SslHandler> getSslHandlerConsumer(final X509Certificate issuer, final X509Certificate httpsCertificateSni) {
        return sslHandler -> {
            if (!(sslHandler.engine() instanceof ReferenceCountedOpenSslEngine engine)) {
                throw new RuntimeException("Unexpected SSL handler type: " + sslHandler.engine());
            }

            // Attempt to retrieve and set the OCSP response here
            try {
                final byte[] ocspResponse = getOcspResponse(issuer, httpsCertificateSni);
                if (ocspResponse != null) {
                    engine.setOcspResponse(ocspResponse);
                } else {
                    System.err.println("Failed to retrieve OCSP response. It is null.");
                }
            } catch (Exception e) {
                throw new RuntimeException("Failed to set OCSP response: " + e.getMessage(), e);
            }
        };
    }

    private static HttpClient setupHttpClient(final X509Certificate rootCa) throws GeneralSecurityException, IOException {
        final KeyStore trustStore = loadKeyStore();
        trustStore.setCertificateEntry("rootCA", rootCa);

        final TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(KEY_MANAGER_ALGORITHM, BC_JSSE_PROVIDER);
        trustManagerFactory.init(trustStore);

        final SSLContext sslContext = SSLContext.getInstance(SSL_CONTEXT_ALGORITHM, BC_JSSE_PROVIDER);
        sslContext.init(null, trustManagerFactory.getTrustManagers(), null);

        return HttpClient.newBuilder()
                .sslContext(sslContext)
                .version(HttpClient.Version.HTTP_1_1)
                .build();
    }

    private static OCSPReq generateOCSPRequest(final X509Certificate issuerCert, final X509Certificate clientCert) throws GeneralSecurityException, IOException, OperatorCreationException, OCSPException {
        final DigestCalculator digestCalculator = new JcaDigestCalculatorProviderBuilder()
                .build()
                .get(CertificateID.HASH_SHA1);
        final X509CertificateHolder issuer = new X509CertificateHolder(issuerCert.getEncoded());
        final CertificateID certificateID = new CertificateID(digestCalculator, issuer, clientCert.getSerialNumber());
        return new OCSPReqBuilder().addRequest(certificateID).build();
    }

    private static OCSPResp sendOCSPRequest(final URI ocspUri, final byte[] ocspRequestBytes) throws IOException, InterruptedException {
        try (final HttpClient httpClient = HttpClient.newHttpClient()) {
            final HttpRequest request = HttpRequest.newBuilder()
                    .uri(ocspUri)
                    .header("Content-Type", "application/ocsp-request")
                    .POST(HttpRequest.BodyPublishers.ofByteArray(ocspRequestBytes))
                    .build();
            final HttpResponse<byte[]> response = httpClient.send(request, HttpResponse.BodyHandlers.ofByteArray());
            return new OCSPResp(response.body());
        }
    }

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
        if (certStatus instanceof RevokedStatus) {
            System.out.println("The certificate is REVOKED.");
            return;
        }
        throw new RuntimeException("The certificate status is UNKNOWN.");
    }

    private static KeyStore loadKeyStore() throws GeneralSecurityException, IOException {
        final KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE, BC_PROVIDER);
        keyStore.load(null, null);
        return keyStore;
    }

    private static byte[] getOcspResponse(final X509Certificate issuer, final X509Certificate certificate) throws OCSPException, GeneralSecurityException, IOException, OperatorCreationException, InterruptedException {
        final OCSPReq ocspRequest = generateOCSPRequest(issuer, certificate);
        final OCSPResp ocspResp = sendOCSPRequest(OCSP_RESPONDER_URL, ocspRequest.getEncoded());

        // Check the response status
        if (ocspResp.getStatus() != OCSPRespBuilder.SUCCESSFUL) {
            System.err.println("OCSP response is not successful: " + ocspResp.getStatus());
            return null;
        }

        final BasicOCSPResp basicResponse = (BasicOCSPResp) ocspResp.getResponseObject();
        return basicResponse.getEncoded(); // Return the DER-encoded OCSP response
    }
}
